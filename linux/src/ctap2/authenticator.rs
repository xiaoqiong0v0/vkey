//! CTAP2 authenticator：GetInfo / MakeCredential / GetAssertion / authenticatorSelection。
//!
//! 与 `spike/uhid_fido.py` 对齐的关键点（`docs/design.md` §8）：
//! - attestation 格式为 `fmt="none"`，attStmt 为空 map
//! - `getInfo.versions` 是 array；不声明 `clientPin`；不声明 `rk`
//! - ES256 签名输出 DER（不是 raw r‖s）
//! - GetAssertion 应答键位按 CTAP2.1 §6.2：1=credential，2=authData，3=signature，
//!   5=numberOfCredentials（以 Chromium 读取顺序为准，见 `docs/evidence/device_response_converter.cc:242-274`）；
//!   不返回 4=user map（M1 无 rk、无 UV，见 `get_assertion_request_handler.cc:138-143`）
//! - 错误应答只返回单个状态字节
//! - 实现 `authenticatorSelection(0x0B)`

use crate::config;
use crate::crypto;
use crate::ctap2::cbor::{self, Value};
use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
pub const CTAP2_ERR_OTHER: u8 = 0x7F;

pub const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP2_GET_ASSERTION: u8 = 0x02;
pub const CTAP2_GET_INFO: u8 = 0x04;
pub const CTAP2_AUTHENTICATOR_SELECTION: u8 = 0x0B;

/// 已知但第一版不实现的命令 → UNSUPPORTED_OPTION。
const CTAP2_UNIMPLEMENTED: &[u8] = &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0D];

const AAGUID: [u8; 16] = [0xA0; 16];
const MAX_MSG_SIZE: u16 = 1200;
const CREDENTIAL_ID_LEN: usize = 32;
const INITIAL_SIGN_COUNT: u32 = 1;

const FLAG_UP: u8 = 0x01;
pub const FLAG_AT: u8 = 0x40;
/// MakeCredential 的 attested credential data 标志（对外别名）。
pub const FLAG_AT_PUBLIC: u8 = FLAG_AT;
const MAKECREDENTIAL_FLAGS: u8 = FLAG_UP | FLAG_AT;
const GETASSERTION_FLAGS: u8 = FLAG_UP;

/// 凭据后端：由本地加密存储或测试内存实现。
pub trait CredentialBackend {
    /// 查找匹配 rp_id（以及可选 allowList）的凭据。
    fn find(&self, rp_id: &str, allow: Option<&[Vec<u8>]>) -> Result<Option<CredentialData>>;
    /// excludeList 判定：指定 rp_id 下是否存在这些 credential_id。
    fn exists(&self, rp_id: &str, credential_ids: &[Vec<u8>]) -> Result<bool>;
    /// 新建凭据（后端负责落盘/加密/同步触发）。
    fn insert(&mut self, new: NewCredential) -> Result<()>;
    /// 更新断言计数器。
    fn update_sign_count(&mut self, credential_id: &[u8], sign_count: u32) -> Result<()>;
}

/// 同步触发器接口（后台线程实现；测试用 Noop）。
pub trait ChangeNotifier: Send + Sync {
    fn notify_change(&self);
}

/// 不做任何事的通知器。
pub struct NoopNotifier;

impl ChangeNotifier for NoopNotifier {
    fn notify_change(&self) {}
}

/// 从后端读出的凭据数据（私钥只在签名瞬间出现在内存）。
#[derive(Clone)]
pub struct CredentialData {
    pub item_id: String,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub private_key_der: Zeroizing<Vec<u8>>,
    pub sign_count: u32,
}

/// 新建凭据的输入。
pub struct NewCredential {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub credential_id: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
    pub sign_count: u32,
}

/// CTAP2 authenticator。
pub struct Authenticator<B: CredentialBackend> {
    backend: B,
}

impl<B: CredentialBackend> Authenticator<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// 访问后端（selftest / 测试用）。
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// 访问可变后端。
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// 取出后端（selftest 结束后取回本地存储）。
    pub fn into_backend(self) -> B {
        self.backend
    }

    /// 处理 CTAPHID_CBOR 载荷（首字节为 CTAP2 命令），返回应答载荷。
    pub fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        let Some(command) = payload.first().copied() else {
            return vec![CTAP2_ERR_INVALID_COMMAND];
        };
        match command {
            CTAP2_GET_INFO => {
                let mut out = vec![CTAP2_OK];
                out.extend_from_slice(&cbor::encode(&get_info_value()));
                out
            }
            CTAP2_AUTHENTICATOR_SELECTION => {
                // Chrome 在多个 authenticator 并存时先发 selection 让用户确认。
                // 第一版不做真实触摸；直接回 OK（与 spike 的 auto-UV 语义一致）。
                vec![CTAP2_OK]
            }
            CTAP2_MAKE_CREDENTIAL | CTAP2_GET_ASSERTION => {
                let request = match cbor::decode(&payload[1..]) {
                    Ok((v, _)) => v,
                    Err(_) => return vec![CTAP2_ERR_INVALID_CBOR],
                };
                if !matches!(request, Value::Map(_)) {
                    return vec![CTAP2_ERR_INVALID_CBOR];
                }
                if command == CTAP2_MAKE_CREDENTIAL {
                    self.make_credential(&request)
                } else {
                    self.get_assertion(&request)
                }
            }
            other if CTAP2_UNIMPLEMENTED.contains(&other) => {
                vec![CTAP2_ERR_UNSUPPORTED_OPTION]
            }
            _ => vec![CTAP2_ERR_INVALID_COMMAND],
        }
    }

    /// authenticatorMakeCredential。
    pub fn make_credential(&mut self, req: &Value) -> Vec<u8> {
        match self.try_make_credential(req) {
            Ok(resp) => {
                let mut out = vec![CTAP2_OK];
                out.extend_from_slice(&cbor::encode(&resp));
                out
            }
            Err(err) => match err.downcast_ref::<CtapError>() {
                Some(ctap) => vec![ctap.0],
                None => vec![CTAP2_ERR_OTHER],
            },
        }
    }

    /// authenticatorGetAssertion。
    pub fn get_assertion(&mut self, req: &Value) -> Vec<u8> {
        match self.try_get_assertion(req) {
            Ok(resp) => {
                let mut out = vec![CTAP2_OK];
                out.extend_from_slice(&cbor::encode(&resp));
                out
            }
            Err(err) => match err.downcast_ref::<CtapError>() {
                Some(ctap) => vec![ctap.0],
                None => vec![CTAP2_ERR_OTHER],
            },
        }
    }

    fn try_make_credential(&mut self, req: &Value) -> Result<Value> {
        let client_hash = req
            .get_int(1)
            .and_then(Value::as_bytes)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?;
        if client_hash.len() != 32 {
            return Err(CtapError(CTAP2_ERR_MISSING_PARAMETER).into());
        }
        let rp = req
            .get_int(2)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?;
        let rp_id = rp
            .get_text("id")
            .and_then(Value::as_text)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?
            .to_string();
        let rp_name = rp
            .get_text("name")
            .and_then(Value::as_text)
            .map(str::to_string);

        let user = req
            .get_int(3)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?;
        let user_handle = user
            .get_text("id")
            .and_then(Value::as_bytes)
            .map(|b| b.to_vec())
            .or_else(|| {
                user.get_int(1)
                    .and_then(Value::as_bytes)
                    .map(|b| b.to_vec())
            })
            .unwrap_or_default();
        let username = user
            .get_text("name")
            .and_then(Value::as_text)
            .map(str::to_string);
        let display_name = user
            .get_text("displayName")
            .and_then(Value::as_text)
            .map(str::to_string);

        // 第一版不声明 rk：RP 强制要求 resident key 时明确拒绝，而不是静默创建不可发现凭据。
        if req
            .get_int(7)
            .and_then(|o| o.get_text("rk"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(CtapError(CTAP2_ERR_UNSUPPORTED_OPTION).into());
        }

        // pubKeyCredParams 必须包含 ES256(-7)。
        if let Some(params) = req.get_int(4).and_then(Value::as_array) {
            let has_es256 = params.iter().any(|p| {
                let alg = p
                    .get_int(3)
                    .and_then(Value::as_i64)
                    .or_else(|| p.get_text("alg").and_then(Value::as_i64));
                let typ = p
                    .get_int(1)
                    .and_then(Value::as_text)
                    .or_else(|| p.get_text("type").and_then(Value::as_text));
                alg == Some(-7) && typ.map(|t| t == "public-key").unwrap_or(true)
            });
            if !has_es256 {
                return Err(CtapError(CTAP2_ERR_UNSUPPORTED_OPTION).into());
            }
        }

        // excludeList：已存在的 credential 直接拒绝，避免重复注册。
        if let Some(list) = req.get_int(5).and_then(Value::as_array) {
            let ids: Vec<Vec<u8>> = list
                .iter()
                .filter_map(|entry| {
                    entry
                        .get_int(1)
                        .and_then(Value::as_bytes)
                        .or_else(|| entry.get_text("id").and_then(Value::as_bytes))
                        .map(|b| b.to_vec())
                })
                .collect();
            if !ids.is_empty() && self.backend.exists(&rp_id, &ids)? {
                return Err(CtapError(CTAP2_ERR_CREDENTIAL_EXCLUDED).into());
            }
        }

        let signing_key = SigningKey::random(&mut OsRng);
        let credential_id = crypto::random_bytes(CREDENTIAL_ID_LEN)?;
        let private_key_der = Zeroizing::new(
            signing_key
                .to_pkcs8_der()
                .map_err(|e| anyhow!("导出 PKCS#8 失败: {e}"))?
                .as_bytes()
                .to_vec(),
        );

        let rp_hash = crypto::sha256(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(MAKECREDENTIAL_FLAGS);
        auth_data.extend_from_slice(&INITIAL_SIGN_COUNT.to_be_bytes());
        auth_data.extend_from_slice(&AAGUID);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&cbor::encode(&cose_key_es256(signing_key.verifying_key())));

        // fmt="none"：attStmt 是空 map，不返回签名。
        self.backend.insert(NewCredential {
            rp_id: rp_id.clone(),
            rp_name,
            user_handle,
            username,
            display_name,
            credential_id,
            private_key_der,
            sign_count: INITIAL_SIGN_COUNT,
        })?;

        Ok(Value::Map(vec![
            (Value::UInt(1), Value::Text("none".into())),
            (Value::UInt(2), Value::Bytes(auth_data)),
            (Value::UInt(3), Value::Map(vec![])),
        ]))
    }

    fn try_get_assertion(&mut self, req: &Value) -> Result<Value> {
        let rp_id = req
            .get_int(1)
            .and_then(Value::as_text)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?
            .to_string();
        let client_hash = req
            .get_int(2)
            .and_then(Value::as_bytes)
            .ok_or(CtapError(CTAP2_ERR_MISSING_PARAMETER))?;
        if client_hash.len() != 32 {
            return Err(CtapError(CTAP2_ERR_MISSING_PARAMETER).into());
        }

        let allow: Option<Vec<Vec<u8>>> = req.get_int(3).and_then(Value::as_array).map(|list| {
            list.iter()
                .filter_map(|entry| {
                    entry
                        .get_int(1)
                        .and_then(Value::as_bytes)
                        .or_else(|| entry.get_text("id").and_then(Value::as_bytes))
                        .map(|b| b.to_vec())
                })
                .collect()
        });

        let credential = self
            .backend
            .find(&rp_id, allow.as_deref())?
            .ok_or(CtapError(CTAP2_ERR_NO_CREDENTIALS))?;

        let sign_count = credential.sign_count.saturating_add(1);
        let signing_key = SigningKey::from_pkcs8_der(&credential.private_key_der)
            .map_err(|e| anyhow!("导入 PKCS#8 失败: {e}"))?;

        let rp_hash = crypto::sha256(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(GETASSERTION_FLAGS);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(client_hash);
        let signature: Signature = signing_key.sign(&message);
        let der = signature.to_der().as_bytes().to_vec();

        self.backend
            .update_sign_count(&credential.credential_id, sign_count)?;

        // 防回归：外层键位以 Chromium `ReadCTAPGetAssertionResponse` 的读取顺序为准
        // （docs/evidence/device_response_converter.cc:242-274）：
        // 0x02=authData（必需，bytestring 且能过 DecodeAuthenticatorData）、0x03=signature、
        // 0x01=credential（PublicKeyCredentialDescriptor）、0x05=numberOfCredentials（unsigned）。
        // 1/2 互换会被判 kCtap2ErrInvalidCBOR。
        //
        // 不下发 0x04（user entity）：WebAuthn L3 规定 `user` 仅在
        // 「discoverable credential 且做了 UV」时返回；本项目 M1 不声明 rk、不做 UV
        // （flags 仅 FLAG_UP，见本文件 GETASSERTION_FLAGS）。带 user 实体（尤其含 "name"）会被
        // Chromium 判为「UV 未置位却返回 user」而拒绝
        // （get_assertion_request_handler.cc:138-143 → NotAllowedError）。
        // 若后续支持 discoverable+UV，再按条件下发。
        //
        // 内层结构用的是**文本键**，不是整数键：
        // - credential 走 `PublicKeyCredentialDescriptor::CreateFromCBORValue`
        //   （.tmp/scratch/156_d.cc:16-17、:23-40）：它按 `map.find(cbor::Value("type"))` /
        //   `("id")` 查找，任何一项缺失或类型不符即 nullopt；外层 0x01 解析失败会让整个响应
        //   变 nullopt，Chrome 合成 kCtap2ErrInvalidCBOR(0x12)
        //   （docs/evidence/device_response_converter.cc:259-266）。
        let response: Vec<(Value, Value)> = vec![
            (
                Value::UInt(1),
                Value::Map(vec![
                    // descriptor 固定为 {"type": "public-key"(text), "id": credentialId(bytes)}。
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (
                        Value::Text("id".into()),
                        Value::Bytes(credential.credential_id.clone()),
                    ),
                ]),
            ),
            // authData：32B rpIdHash ‖ 1B flags(0x01) ‖ 4B signCount = 37B。
            (Value::UInt(2), Value::Bytes(auth_data)),
            (Value::UInt(3), Value::Bytes(der)),
            // numberOfCredentials 可选，这里恒为单凭据。
            (Value::UInt(5), Value::UInt(1)),
        ];
        Ok(Value::Map(response))
    }
}

/// 把 CTAP2 authenticator 接到 CTAPHID 状态机（`CtapHid` 的处理器）。
impl<B: CredentialBackend> crate::ctap2::hid::Ctap2Handler for Authenticator<B> {
    fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        Authenticator::handle_cbor(self, payload)
    }
}

/// authenticatorGetInfo 应答体。
pub fn get_info_value() -> Value {
    Value::Map(vec![
        (
            Value::UInt(1),
            Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("FIDO_2_1".into()),
            ]),
        ),
        (Value::UInt(3), Value::Bytes(AAGUID.to_vec())),
        (
            Value::UInt(4),
            Value::Map(vec![
                (Value::Text("up".into()), Value::Bool(true)),
                (Value::Text("plat".into()), Value::Bool(false)),
            ]),
        ),
        (Value::UInt(5), Value::UInt(u64::from(MAX_MSG_SIZE))),
        (
            Value::UInt(9),
            Value::Array(vec![Value::Text("usb".into())]),
        ),
        (
            Value::UInt(10),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), Value::NInt(-7)),
            ])]),
        ),
    ])
}

/// 把 P-256 公钥编码为 COSE_Key `{1:2, 3:-7, -1:1, -2:x, -3:y}`。
pub fn cose_key_es256(public_key: &VerifyingKey) -> Value {
    let point = public_key.to_encoded_point(false);
    let x = point.x().expect("非压缩点必须有 x").to_vec();
    let y = point.y().expect("非压缩点必须有 y").to_vec();
    Value::Map(vec![
        (Value::UInt(1), Value::UInt(2)),  // kty: EC2
        (Value::UInt(3), Value::NInt(-7)), // alg: ES256
        (Value::NInt(-1), Value::UInt(1)), // crv: P-256
        (Value::NInt(-2), Value::Bytes(x)),
        (Value::NInt(-3), Value::Bytes(y)),
    ])
}

/// 从 PKCS#8 DER 私钥导出 COSE_Key（测试 / 跨设备验签用）。
pub fn cose_key_from_pkcs8(der: &[u8]) -> Result<Value> {
    let signing_key =
        SigningKey::from_pkcs8_der(der).map_err(|e| anyhow!("导入 PKCS#8 失败: {e}"))?;
    Ok(cose_key_es256(signing_key.verifying_key()))
}

/// 校验 COSE_Key 对 `message` 的 DER 签名（selftest / 测试用）。
pub fn verify_cose_signature(cose: &Value, message: &[u8], der_signature: &[u8]) -> Result<()> {
    if cose.get_int(1).and_then(Value::as_i64) != Some(2) {
        bail!("COSE kty 不是 EC2");
    }
    if cose.get_int(3).and_then(Value::as_i64) != Some(-7) {
        bail!("COSE alg 不是 ES256");
    }
    let x = cose
        .get_int(-2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("COSE 缺少 x"))?;
    let y = cose
        .get_int(-3)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("COSE 缺少 y"))?;
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1)?;
    let sig = Signature::from_der(der_signature)?;
    vk.verify(message, &sig)
        .map_err(|e| anyhow!("DER 验签失败: {e}"))
}

/// 解析 authenticatorData，返回 (rpIdHash, flags, signCount, 可选 attested data)。
pub struct ParsedAuthData<'a> {
    pub rp_id_hash: &'a [u8],
    pub flags: u8,
    pub sign_count: u32,
    pub credential_id: Option<&'a [u8]>,
    pub cose_key: Option<Value>,
}

/// 解析 authenticatorData（MakeCredential 含 attested credential data）。
pub fn parse_auth_data(data: &[u8]) -> Result<ParsedAuthData<'_>> {
    if data.len() < 37 {
        bail!("authenticatorData 过短");
    }
    let rp_id_hash = &data[..32];
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    if flags & FLAG_AT == 0 {
        return Ok(ParsedAuthData {
            rp_id_hash,
            flags,
            sign_count,
            credential_id: None,
            cose_key: None,
        });
    }
    if data.len() < 37 + 16 + 2 {
        bail!("attested credential data 过短");
    }
    let mut pos = 37 + 16;
    let cred_len = usize::from(u16::from_be_bytes([data[pos], data[pos + 1]]));
    pos += 2;
    if data.len() < pos + cred_len {
        bail!("credentialId 截断");
    }
    let credential_id = &data[pos..pos + cred_len];
    pos += cred_len;
    let (cose, _) = cbor::decode(&data[pos..]).context("解析 COSE_Key 失败")?;
    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id: Some(credential_id),
        cose_key: Some(cose),
    })
}

impl std::fmt::Debug for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CtapError(0x{:02X})", self.0)
    }
}

impl std::fmt::Display for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CTAP2 错误 0x{:02X}", self.0)
    }
}

/// 内部错误类型：携带 CTAP2 状态码。
struct CtapError(u8);

impl std::error::Error for CtapError {}

/// 测试 / selftest 用内存后端。
#[derive(Default)]
pub struct MemoryBackend {
    credentials: Vec<CredentialData>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

impl CredentialBackend for MemoryBackend {
    fn find(&self, rp_id: &str, allow: Option<&[Vec<u8>]>) -> Result<Option<CredentialData>> {
        for cred in &self.credentials {
            if cred.rp_id != rp_id {
                continue;
            }
            if let Some(allow) = allow {
                if !allow.is_empty() && !allow.iter().any(|id| id == &cred.credential_id) {
                    continue;
                }
            }
            return Ok(Some(cred.clone()));
        }
        Ok(None)
    }

    fn exists(&self, rp_id: &str, credential_ids: &[Vec<u8>]) -> Result<bool> {
        Ok(self
            .credentials
            .iter()
            .any(|c| c.rp_id == rp_id && credential_ids.iter().any(|id| id == &c.credential_id)))
    }

    fn insert(&mut self, new: NewCredential) -> Result<()> {
        self.credentials.push(CredentialData {
            item_id: format!("mem-{}", self.credentials.len()),
            rp_id: new.rp_id,
            user_handle: new.user_handle,
            credential_id: new.credential_id,
            username: new.username,
            display_name: new.display_name,
            private_key_der: new.private_key_der,
            sign_count: new.sign_count,
        });
        Ok(())
    }

    fn update_sign_count(&mut self, credential_id: &[u8], sign_count: u32) -> Result<()> {
        let cred = self
            .credentials
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
            .ok_or_else(|| anyhow!("credential 不存在"))?;
        cred.sign_count = sign_count;
        Ok(())
    }
}

/// 构造一个 makeCredential 请求（测试 / selftest 用）。
pub fn make_credential_request(rp_id: &str, user_handle: &[u8], client_hash: &[u8]) -> Value {
    Value::Map(vec![
        (Value::UInt(1), Value::Bytes(client_hash.to_vec())),
        (
            Value::UInt(2),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text(rp_id.into())),
                (Value::Text("name".into()), Value::Text(rp_id.into())),
            ]),
        ),
        (
            Value::UInt(3),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(user_handle.to_vec())),
                (Value::Text("name".into()), Value::Text("selftest".into())),
                (
                    Value::Text("displayName".into()),
                    Value::Text("Selftest".into()),
                ),
            ]),
        ),
        (
            Value::UInt(4),
            Value::Array(vec![Value::Map(vec![
                (Value::UInt(1), Value::Text("public-key".into())),
                (Value::UInt(3), Value::NInt(-7)),
            ])]),
        ),
    ])
}

/// 构造一个 getAssertion 请求（测试 / selftest 用）。
pub fn get_assertion_request(
    rp_id: &str,
    client_hash: &[u8],
    credential_id: Option<&[u8]>,
) -> Value {
    let mut entries = vec![
        (Value::UInt(1), Value::Text(rp_id.into())),
        (Value::UInt(2), Value::Bytes(client_hash.to_vec())),
    ];
    if let Some(id) = credential_id {
        entries.push((
            Value::UInt(3),
            Value::Array(vec![Value::Map(vec![
                (Value::UInt(1), Value::Bytes(id.to_vec())),
                (Value::UInt(2), Value::Text("public-key".into())),
            ])]),
        ));
    }
    Value::Map(entries)
}

/// 检查当前时间戳（保留给未来 UV/超时逻辑；selftest 输出用）。
pub fn now() -> i64 {
    config::now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hash(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    #[test]
    fn make_and_get_assertion_with_der_verify() {
        let backend = MemoryBackend::new();
        let mut auth = Authenticator::new(backend);
        let create = make_credential_request("example.com", b"user-1", &client_hash(7));
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        assert_eq!(resp[0], CTAP2_OK);
        let (created, _) = cbor::decode(&resp[1..]).unwrap();
        assert_eq!(
            created.get_int(1).and_then(Value::as_text),
            Some("none"),
            "attestation fmt 必须是 none"
        );
        let auth_data = created.get_int(2).and_then(Value::as_bytes).unwrap();
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.rp_id_hash, crypto::sha256(b"example.com"));
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.sign_count, INITIAL_SIGN_COUNT);
        let cose = parsed.cose_key.clone().unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        let hash2 = client_hash(9);
        let get = get_assertion_request("example.com", &hash2, Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp[0], CTAP2_OK);
        let (assertion, _) = cbor::decode(&resp[1..]).unwrap();
        let auth_data = assertion.get_int(2).and_then(Value::as_bytes).unwrap();
        let sig = assertion.get_int(3).and_then(Value::as_bytes).unwrap();
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.sign_count, 2);
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&hash2);
        verify_cose_signature(&cose, &msg, sig).expect("DER 签名必须验证通过");

        let descriptor = assertion.get_int(1).unwrap();
        assert_eq!(
            descriptor.get_text("type").and_then(Value::as_text),
            Some("public-key")
        );
        assert_eq!(
            descriptor.get_text("id").and_then(Value::as_bytes),
            Some(&cred_id[..])
        );
    }

    /// 回归：GetAssertion 应答键位必须与 Chromium `ReadCTAPGetAssertionResponse` 一致
    /// （docs/evidence/device_response_converter.cc:242-274）：1=credential，2=authData，
    /// 3=signature，5=numberOfCredentials；不得含 4=user（M1 无 rk/无 UV）。
    /// 1/2 互换会被判 kCtap2ErrInvalidCBOR。
    #[test]
    fn get_assertion_response_follows_ctap21_key_layout() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let user_handle = b"user-regress".to_vec();
        let create = make_credential_request("example.com", &user_handle, &client_hash(3));
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        assert_eq!(resp[0], CTAP2_OK);
        let (created, _) = cbor::decode(&resp[1..]).unwrap();
        let parsed =
            parse_auth_data(created.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        let cose = parsed.cose_key.clone().unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        let hash = client_hash(4);
        let get = get_assertion_request("example.com", &hash, Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp[0], CTAP2_OK);
        let (assertion, _) = cbor::decode(&resp[1..]).unwrap();

        // key1 必须是 PublicKeyCredentialDescriptor map：{"type":"public-key", "id":credentialId}，
        // 文本键缺一即 CreateFromCBORValue 返回 nullopt（.tmp/scratch/156_d.cc:16-17、:23-40），
        // 外层整包被判 kCtap2ErrInvalidCBOR（docs/evidence/device_response_converter.cc:259-266）。
        let descriptor = assertion
            .get_int(1)
            .expect("key1 必须是 credential descriptor");
        assert!(matches!(descriptor, Value::Map(_)), "key1 必须是 map");
        assert_eq!(
            descriptor.get_text("type").and_then(Value::as_text),
            Some("public-key")
        );
        assert_eq!(
            descriptor.get_text("id").and_then(Value::as_bytes),
            Some(&cred_id[..])
        );

        // key2 必须是 authData bytes：32 字节 rpIdHash + 1 字节 flags + 4 字节 signCount。
        let auth_data = assertion
            .get_int(2)
            .and_then(Value::as_bytes)
            .expect("key2 必须是 authData bytes（不能是 descriptor map）");
        assert_eq!(auth_data.len(), 37, "GetAssertion authData 长度必须是 37");

        // key3 必须是 DER 签名，且能对 authData ‖ clientHash 验签。
        let sig = assertion
            .get_int(3)
            .and_then(Value::as_bytes)
            .expect("key3 必须是 signature bytes");
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&hash);
        verify_cose_signature(&cose, &msg, sig).expect("DER 签名必须验证通过");

        // key4 不得出现：M1 无 rk、不做 UV（flags 仅 FLAG_UP），WebAuthn L3 规定
        // 非 discoverable / 未 UV 时不得返回 user 实体；否则 Chromium 拒绝
        // （get_assertion_request_handler.cc:138-143 → NotAllowedError）。
        assert!(
            assertion.get_int(4).is_none(),
            "非 discoverable + 无 UV 时响应不得带 user 实体（key 4）"
        );

        // key5 可选 numberOfCredentials，Chromium 要求是 unsigned。
        assert_eq!(
            assertion.get_int(5).and_then(Value::as_i64),
            Some(1),
            "numberOfCredentials 必须是 unsigned 1"
        );
    }

    #[test]
    fn get_assertion_without_matching_credential_returns_2e() {
        let mut backend = MemoryBackend::new();
        let mut auth = Authenticator::new(std::mem::take(&mut backend));
        let create = make_credential_request("a.example", b"u", &client_hash(1));
        assert_eq!(
            auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat())[0],
            CTAP2_OK
        );

        let get = get_assertion_request("b.example", &client_hash(2), None);
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);

        let get = get_assertion_request("a.example", &client_hash(2), Some(b"unknown"));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);
    }

    #[test]
    fn multiple_credentials_select_by_allow_list() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        // 第一颗
        let req1 = make_credential_request("example.com", b"u1", &client_hash(1));
        assert_eq!(
            auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req1)].concat())[0],
            CTAP2_OK
        );
        let req2 = make_credential_request("example.com", b"u2", &client_hash(2));
        let resp2 = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req2)].concat());
        let (created2, _) = cbor::decode(&resp2[1..]).unwrap();
        let parsed2 =
            parse_auth_data(created2.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        let id2 = parsed2.credential_id.unwrap().to_vec();

        let get = get_assertion_request("example.com", &client_hash(3), Some(&id2));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp[0], CTAP2_OK);
        let (assertion, _) = cbor::decode(&resp[1..]).unwrap();
        let descriptor = assertion.get_int(1).unwrap();
        assert_eq!(
            descriptor.get_text("id").and_then(Value::as_bytes),
            Some(&id2[..]),
            "必须选中 allowList 指定的凭据"
        );
    }

    #[test]
    fn get_info_has_array_versions_and_no_client_pin() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let resp = auth.handle_cbor(&[CTAP2_GET_INFO]);
        assert_eq!(resp[0], CTAP2_OK);
        let (info, _) = cbor::decode(&resp[1..]).unwrap();
        assert!(matches!(info.get_int(1), Some(Value::Array(_))));
        assert!(info.get_int(6).is_none(), "不能声明 clientPin");
        assert!(info.get_int(2).is_none(), "不能声明 rk 相关字段");
        let options = info.get_int(4).unwrap();
        assert_eq!(options.get_text("up").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn rk_option_is_rejected() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let mut req = make_credential_request("example.com", b"u", &client_hash(1));
        if let Value::Map(entries) = &mut req {
            entries.push((
                Value::UInt(7),
                Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
            ));
        }
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_UNSUPPORTED_OPTION]);
    }

    #[test]
    fn authenticator_selection_returns_ok() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let req = Value::Map(vec![(Value::UInt(1), Value::Text("example.com".into()))]);
        let resp =
            auth.handle_cbor(&[vec![CTAP2_AUTHENTICATOR_SELECTION], cbor::encode(&req)].concat());
        assert_eq!(resp, vec![CTAP2_OK]);
    }

    #[test]
    fn invalid_cbor_is_single_byte_error() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let resp = auth.handle_cbor(&[CTAP2_GET_ASSERTION, 0xFF]);
        assert_eq!(resp, vec![CTAP2_ERR_INVALID_CBOR]);
        assert_eq!(resp.len(), 1);
    }
}
