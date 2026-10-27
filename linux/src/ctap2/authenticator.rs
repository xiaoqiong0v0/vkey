//! CTAP2 authenticator：GetInfo / MakeCredential / GetAssertion / authenticatorSelection。
//!
//! 与 `spike/uhid_fido.py` 对齐的关键点（`docs/design.md` §8）：
//! - attestation 格式为 `fmt="none"`，attStmt 为空 map
//! - `getInfo.versions` 是 array；不声明 `clientPin`；声明 `rk` / `uv`（UV 口径见 `linux/README.md`）
//! - ES256 签名输出 DER（不是 raw r‖s）
//! - GetAssertion 应答键位按 CTAP2.1 §6.2：1=credential，2=authData，3=signature，
//!   5=numberOfCredentials（以 Chromium 读取顺序为准，见 `docs/evidence/device_response_converter.cc:242-274`）；
//!   4=user 实体仅在「allowList 为空的可发现凭据路径」返回
//! - 发往 CTAPHID 的应答：成功为 `0x00` + CBOR 载荷（`CTAP2_OK` 状态字节打头），错误只返回单个状态字节
//! - 实现 `authenticatorSelection(0x0B)`

use crate::config;
use crate::crypto;
use crate::ctap2::cbor::{self, Value};
use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// `VKEY_CTAP_DEBUG=1` 时的 CBOR 调试日志开关（进程内只读一次）。
static CTAP_DEBUG: OnceLock<bool> = OnceLock::new();

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

// 请求键位（调试摘要用，CTAP2.1 §6.1 makeCredential / §6.2 getAssertion）。
const MC_RP: i64 = 2;
const MC_PUB_KEY_CRED_PARAMS: i64 = 4;
const MC_EXCLUDE_LIST: i64 = 5;
const MC_EXTENSIONS: i64 = 6;
const MC_OPTIONS: i64 = 7;
const MC_ENTERPRISE_ATTESTATION: i64 = 10;
const GA_RP_ID: i64 = 1;
const GA_ALLOW_LIST: i64 = 3;
const GA_EXTENSIONS: i64 = 4;
const GA_OPTIONS: i64 = 5;
/// 摘要里空列表 / 缺省布尔项的占位符。
const DETAIL_EMPTY: &str = "-";
const DETAIL_UNSPECIFIED: &str = "unspecified";

/// CTAP2 内部应答：成功是 CBOR 载荷（`authenticatorSelection` 为空），失败是单字节状态码。
///
/// 这是内部表示，**不含**状态字节；发到 CTAPHID 前由 `handle_cbor` 统一前置
/// `CTAP2_OK`。原因是 Chromium 的 CTAPHID 层把响应首字节当状态码读取
/// （实测：不带 `0x00` 时把 CBOR map 头 `0xA6` 读成 `166`，即 `0xA6`）。
pub type CtapResponse = std::result::Result<Vec<u8>, u8>;

const AAGUID: [u8; 16] = [0xA0; 16];
const MAX_MSG_SIZE: u16 = 1200;
const CREDENTIAL_ID_LEN: usize = 32;
const INITIAL_SIGN_COUNT: u32 = 1;

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
/// MakeCredential 的 attested credential data 标志（对外别名）。
pub const FLAG_AT_PUBLIC: u8 = FLAG_AT;
const MAKECREDENTIAL_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_AT;
const GETASSERTION_FLAGS: u8 = FLAG_UP | FLAG_UV;

/// 凭据后端：由本地加密存储或测试内存实现。
pub trait CredentialBackend {
    /// 查找匹配 rp_id 的凭据列表。
    ///
    /// - `allow` 非空时只保留 credential_id 命中的条目；
    /// - `discoverable_only=true` 时只保留可发现凭据（`discoverable=true`）；
    /// - 返回顺序由后端决定（本地存储为 `items.json` 的迭代顺序），调用方在此顺序上做稳定选择。
    fn find(
        &self,
        rp_id: &str,
        allow: Option<&[Vec<u8>]>,
        discoverable_only: bool,
    ) -> Result<Vec<CredentialData>>;
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
    /// 是否为可发现凭据（MakeCredential 请求了 options.rk=true）。
    pub discoverable: bool,
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
    /// 是否为可发现凭据（MakeCredential 请求了 options.rk=true）。
    pub discoverable: bool,
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
    ///
    /// 这里是发往 CTAPHID 的边界：成功应答统一前置状态字节 `CTAP2_OK`，
    /// 失败保持单字节状态码。Chromium 的 CTAPHID 层把首字节当状态码，
    /// 不带 `0x00` 时会把 CBOR map 头读成状态码（实测 `166` = `0xA6`）。
    ///
    /// `VKEY_CTAP_DEBUG=1` 时向 stderr 打印一行请求 / 一行应答（默认零输出）；
    /// 应答日志按 `Result` 分支打印，不靠首字节猜测。
    pub fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
        let debug = ctap_debug_enabled();
        let command = payload.first().copied();
        if debug {
            eprintln!("CTAP req cmd={} in={}", cmd_label(command), payload.len());
        }
        let response = self.handle_cbor_inner(payload);
        if debug {
            eprintln!(
                "CTAP resp cmd={} {}",
                cmd_label(command),
                resp_summary(&response)
            );
        }
        to_hid_payload(response)
    }

    /// `handle_cbor` 的实现体（不含调试日志与状态字节）。
    ///
    /// 成功返回 CBOR 载荷，失败返回单字节状态码；状态字节由 `to_hid_payload` 补齐。
    fn handle_cbor_inner(&mut self, payload: &[u8]) -> CtapResponse {
        let Some(command) = payload.first().copied() else {
            return Err(CTAP2_ERR_INVALID_COMMAND);
        };
        match command {
            CTAP2_GET_INFO => Ok(cbor::encode(&get_info_value())),
            CTAP2_AUTHENTICATOR_SELECTION => {
                // Chrome 在多个 authenticator 并存时先发 selection 让用户确认。
                // 第一版不做真实触摸；直接成功（与 spike 的 auto-UV 语义一致）。
                // 内部载荷为空，边界补 `CTAP2_OK` 后即为单字节应答。
                Ok(Vec::new())
            }
            CTAP2_MAKE_CREDENTIAL | CTAP2_GET_ASSERTION => {
                let request = match cbor::decode(&payload[1..]) {
                    Ok((v, _)) => v,
                    Err(_) => {
                        log_request_detail_failed();
                        return Err(CTAP2_ERR_INVALID_CBOR);
                    }
                };
                if !matches!(request, Value::Map(_)) {
                    log_request_detail_failed();
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                // 调试期（`VKEY_CTAP_DEBUG=1`）额外打印一行结构化摘要，用于定位
                // 浏览器 / npm 实际发来的 rp、options、扩展等参数。
                if ctap_debug_enabled() {
                    eprintln!("{}", request_detail_line(command, &request));
                }
                if command == CTAP2_MAKE_CREDENTIAL {
                    self.make_credential(&request)
                } else {
                    self.get_assertion(&request)
                }
            }
            other if CTAP2_UNIMPLEMENTED.contains(&other) => Err(CTAP2_ERR_UNSUPPORTED_OPTION),
            _ => Err(CTAP2_ERR_INVALID_COMMAND),
        }
    }

    /// authenticatorMakeCredential。
    pub fn make_credential(&mut self, req: &Value) -> CtapResponse {
        match self.try_make_credential(req) {
            Ok(resp) => Ok(cbor::encode(&resp)),
            Err(err) => Err(ctap_status(&err)),
        }
    }

    /// authenticatorGetAssertion。
    pub fn get_assertion(&mut self, req: &Value) -> CtapResponse {
        match self.try_get_assertion(req) {
            Ok(resp) => Ok(cbor::encode(&resp)),
            Err(err) => Err(ctap_status(&err)),
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

        // CTAP2 MakeCredential 的 options 在 key 7。只有 RP 明确要求 rk=true 时才存为
        // 可发现凭据；UV 采用「up 即 uv」的本机信任口径，options.uv 的取值不影响接受与否。
        let rk = req
            .get_int(7)
            .and_then(|o| o.get_text("rk"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

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
        // flags = UP | UV | AT(0x40)。WebAuthn/CTAP2 没有独立的 RK 位：0x40 是
        // 「attested credential data included」，MakeCredential 必须恒置；
        // 可发现性由条目字段 discoverable 与 GetAssertion 的 user 实体表达。
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
            discoverable: rk,
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

        // 空 allowList 是 WebAuthn「可发现凭据」路径：只在 discoverable=true 的条目中选。
        // 非空 allowList 保持原有行为：按 credential_id 匹配，不要求 discoverable。
        let (candidates, discoverable_path) = match allow.as_deref() {
            Some(list) if !list.is_empty() => {
                (self.backend.find(&rp_id, Some(list), false)?, false)
            }
            _ => (self.backend.find(&rp_id, None, true)?, true),
        };
        if candidates.is_empty() {
            return Err(CtapError(CTAP2_ERR_NO_CREDENTIALS).into());
        }

        let number_of_credentials = candidates.len();
        let credential = if discoverable_path {
            // 固定选择策略：sign_count 最大者优先（最近使用）；相同时取后端返回顺序的第一个。
            select_discoverable(candidates)
        } else {
            candidates
                .into_iter()
                .next()
                .expect("candidates 已确认非空")
        };

        let sign_count = credential.sign_count.saturating_add(1);
        let signing_key = SigningKey::from_pkcs8_der(&credential.private_key_der)
            .map_err(|e| anyhow!("导入 PKCS#8 失败: {e}"))?;

        let rp_hash = crypto::sha256(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_hash);
        // flags = UP | UV。这里不置 0x40：CTAP2/WebAuthn 的 0x40 是 AT
        // （attested credential data），GetAssertion 不带该数据；置位会让 Chromium
        // 的 DecodeAuthenticatorData 尝试解析 attested data 并把整包判为 InvalidCBOR
        // （.tmp/scratch/156_authenticator_data.cc:68-72），且
        // get_assertion_request_handler.cc 明确拒绝 attested_data。
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
        // 0x04（user entity）只在「allowList 为空」的可发现凭据路径返回；WebAuthn L3 /
        // Chromium 要求该路径必须有 user 实体，且 user 带 name/displayName 时必须已有 UV
        // （get_assertion_request_handler.cc:120-148）。allowList 路径保持不返回 user。
        //
        // 内层结构用的是**文本键**，不是整数键：
        // - credential 走 `PublicKeyCredentialDescriptor::CreateFromCBORValue`
        //   （.tmp/scratch/156_d.cc:16-17、:23-40）：它按 `map.find(cbor::Value("type"))` /
        //   `("id")` 查找，任何一项缺失或类型不符即 nullopt；外层 0x01 解析失败会让整个响应
        //   变 nullopt，Chrome 合成 kCtap2ErrInvalidCBOR(0x12)
        //   （docs/evidence/device_response_converter.cc:259-266）。
        let mut response: Vec<(Value, Value)> = vec![
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
            // authData：32B rpIdHash ‖ 1B flags(UP|UV = 0x05) ‖ 4B signCount = 37B。
            (Value::UInt(2), Value::Bytes(auth_data)),
            (Value::UInt(3), Value::Bytes(der)),
            // numberOfCredentials：可发现路径为 rp_id 下可发现凭据总数；allowList 路径为匹配数。
            (Value::UInt(5), Value::UInt(number_of_credentials as u64)),
        ];
        if discoverable_path {
            response.push((Value::UInt(4), user_entity(&credential)));
        }
        Ok(Value::Map(response))
    }
}

/// 从可发现凭据中选一个：`sign_count` 最大者优先；相同时保留后端返回顺序的第一个。
fn select_discoverable(candidates: Vec<CredentialData>) -> CredentialData {
    let mut best: Option<CredentialData> = None;
    for candidate in candidates {
        let replace = match best.as_ref() {
            None => true,
            Some(current) => candidate.sign_count > current.sign_count,
        };
        if replace {
            best = Some(candidate);
        }
    }
    best.expect("可发现凭据列表已确认非空")
}

/// 构造 GetAssertion 的 user 实体（文本键，`id` 必填）。
fn user_entity(credential: &CredentialData) -> Value {
    let mut entries = vec![(
        Value::Text("id".into()),
        Value::Bytes(credential.user_handle.clone()),
    )];
    if let Some(name) = credential.username.as_deref().filter(|s| !s.is_empty()) {
        entries.push((Value::Text("name".into()), Value::Text(name.to_string())));
    }
    if let Some(display_name) = credential.display_name.as_deref().filter(|s| !s.is_empty()) {
        entries.push((
            Value::Text("displayName".into()),
            Value::Text(display_name.to_string()),
        ));
    }
    Value::Map(entries)
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
                (Value::Text("rk".into()), Value::Bool(true)),
                (Value::Text("up".into()), Value::Bool(true)),
                // UV 口径 = 「up 即 uv」（软件密钥、本机进程可信），见 linux/README.md。
                (Value::Text("uv".into()), Value::Bool(true)),
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

/// 把内部错误映射为 CTAP2 状态码（非 `CtapError` 统一归为 `CTAP2_ERR_OTHER`）。
fn ctap_status(err: &anyhow::Error) -> u8 {
    match err.downcast_ref::<CtapError>() {
        Some(ctap) => ctap.0,
        None => CTAP2_ERR_OTHER,
    }
}

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
    fn find(
        &self,
        rp_id: &str,
        allow: Option<&[Vec<u8>]>,
        discoverable_only: bool,
    ) -> Result<Vec<CredentialData>> {
        let mut out = Vec::new();
        for cred in &self.credentials {
            if cred.rp_id != rp_id {
                continue;
            }
            if discoverable_only && !cred.discoverable {
                continue;
            }
            if let Some(allow) = allow {
                if !allow.is_empty() && !allow.iter().any(|id| id == &cred.credential_id) {
                    continue;
                }
            }
            out.push(cred.clone());
        }
        Ok(out)
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
            discoverable: new.discoverable,
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

/// 构造一个 makeCredential 请求（测试 / selftest 用；默认不请求 rk）。
pub fn make_credential_request(rp_id: &str, user_handle: &[u8], client_hash: &[u8]) -> Value {
    make_credential_request_with_rk(rp_id, user_handle, client_hash, false)
}

/// 构造一个 makeCredential 请求，并按需声明 `options.rk=true`。
pub fn make_credential_request_with_rk(
    rp_id: &str,
    user_handle: &[u8],
    client_hash: &[u8],
    rk: bool,
) -> Value {
    let mut entries = vec![
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
    ];
    if rk {
        entries.push((
            Value::UInt(7),
            Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
        ));
    }
    Value::Map(entries)
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

/// CBOR 调试日志是否开启（`VKEY_CTAP_DEBUG=1`）。
fn ctap_debug_enabled() -> bool {
    crate::ctap2::debug_flag(&CTAP_DEBUG, "VKEY_CTAP_DEBUG")
}

/// 命令字节的日志表示（空载荷时无命令字节）。
fn cmd_label(command: Option<u8>) -> String {
    match command {
        Some(command) => format!("0x{command:02x}"),
        None => "<empty>".to_string(),
    }
}

/// 应答的日志表示：成功打印载荷长度，失败打印状态码（按 `Result` 分支，不猜首字节）。
fn resp_summary(response: &CtapResponse) -> String {
    match response {
        Ok(body) => format!("out={} ok", body.len()),
        Err(status) => format!("status=0x{status:02x}"),
    }
}

/// 把内部应答转换为发往 CTAPHID 的载荷：成功前置 `CTAP2_OK`，失败保持单字节状态码。
fn to_hid_payload(response: CtapResponse) -> Vec<u8> {
    match response {
        Ok(body) => {
            let mut out = Vec::with_capacity(body.len() + 1);
            out.push(CTAP2_OK);
            out.extend_from_slice(&body);
            out
        }
        Err(status) => vec![status],
    }
}

/// 请求摘要解析失败时的调试输出（仅 `VKEY_CTAP_DEBUG=1` 生效，不 panic）。
fn log_request_detail_failed() {
    if ctap_debug_enabled() {
        eprintln!("CTAP req-detail parse=failed");
    }
}

/// 生成 makeCredential / getAssertion 请求的**一行结构化摘要**（仅调试日志用）。
///
/// 只输出字段摘要（不打印整段 hex）；必填字段（`rp.id` / `rpId`）解析不出时
/// 返回 `CTAP req-detail parse=failed`，调用方直接打印即可。
///
/// - `command`：CTAP2 命令字节（0x01 / 0x02）；
/// - `req`：已解码的 CBOR 请求 map。
fn request_detail_line(command: u8, req: &Value) -> String {
    let fields = match command {
        CTAP2_MAKE_CREDENTIAL => make_credential_detail(req),
        CTAP2_GET_ASSERTION => get_assertion_detail(req),
        _ => None,
    };
    match fields {
        Some(fields) => format!("CTAP req-detail cmd=0x{command:02x} {fields}"),
        None => "CTAP req-detail parse=failed".to_string(),
    }
}

/// makeCredential 摘要字段；缺少 rp.id 时返回 `None`（由调用方输出 parse=failed）。
fn make_credential_detail(req: &Value) -> Option<String> {
    let rp_id = req
        .get_int(MC_RP)?
        .get_text("id")
        .and_then(Value::as_text)?;
    let rk = option_bool(req, MC_OPTIONS, "rk").unwrap_or(false);
    let uv = option_bool(req, MC_OPTIONS, "uv");
    let algs = public_key_algs(req.get_int(MC_PUB_KEY_CRED_PARAMS));
    let attestation = attestation_label(req.get_int(MC_ENTERPRISE_ATTESTATION));
    let exts = extension_keys(req.get_int(MC_EXTENSIONS));
    let exclude = array_len(req.get_int(MC_EXCLUDE_LIST));
    Some(format!(
        "rp_id={rp_id} rk={rk} uv={} alg={} attestation={attestation} exts={} exclude={exclude}",
        optional_bool_label(uv),
        join_or_dash(&algs),
        join_or_dash(&exts),
    ))
}

/// getAssertion 摘要字段；缺少 rpId 时返回 `None`（由调用方输出 parse=failed）。
fn get_assertion_detail(req: &Value) -> Option<String> {
    let rp_id = req.get_int(GA_RP_ID).and_then(Value::as_text)?;
    let uv = option_bool(req, GA_OPTIONS, "uv");
    // CTAP2.1 §6.2：options.up 缺省为 true（不声明即表示要用户确认）。
    let up = option_bool(req, GA_OPTIONS, "up").unwrap_or(true);
    // 空 allowList（含字段缺失）即 WebAuthn 可发现凭据路径。
    let allow = match array_len(req.get_int(GA_ALLOW_LIST)) {
        0 => "empty".to_string(),
        n => n.to_string(),
    };
    let exts = extension_keys(req.get_int(GA_EXTENSIONS));
    Some(format!(
        "rp_id={rp_id} uv={} allow={allow} exts={} up={up}",
        optional_bool_label(uv),
        join_or_dash(&exts),
    ))
}

/// 读取请求 options map 中的布尔项；字段或选项缺失时返回 `None`。
fn option_bool(req: &Value, options_key: i64, name: &str) -> Option<bool> {
    req.get_int(options_key)
        .and_then(|options| options.get_text(name))
        .and_then(Value::as_bool)
}

/// `pubKeyCredParams` 里的 alg 列表（兼容整数键 `3` 与文本键 `alg`）。
fn public_key_algs(params: Option<&Value>) -> Vec<String> {
    params
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|entry| {
                    entry
                        .get_int(3)
                        .and_then(Value::as_i64)
                        .or_else(|| entry.get_text("alg").and_then(Value::as_i64))
                        .map(|alg| alg.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// extensions map 的键名列表（文本键为主，整数键按十进制输出）。
fn extension_keys(extensions: Option<&Value>) -> Vec<String> {
    match extensions {
        Some(Value::Map(entries)) => entries
            .iter()
            .filter_map(|(key, _)| match key {
                Value::Text(name) => Some(name.clone()),
                Value::UInt(n) => Some(n.to_string()),
                Value::NInt(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// attestation 字段：CTAP2 只承载 enterpriseAttestation（非 0 即企业证明），
/// 其余情况按实现口径视为 `none`（本实现恒返回 `fmt="none"`）。
fn attestation_label(enterprise: Option<&Value>) -> &'static str {
    match enterprise.and_then(Value::as_i64) {
        Some(value) if value > 0 => "enterprise",
        _ => "none",
    }
}

/// 数组字段长度；字段缺失或类型不符时按 0 处理。
fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, <[Value]>::len)
}

/// 列表转日志文本：空列表输出占位符 `-`。
fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        DETAIL_EMPTY.to_string()
    } else {
        items.join(",")
    }
}

/// 可选布尔项的日志文本：缺省输出 `unspecified`。
fn optional_bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => DETAIL_UNSPECIFIED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hash(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// 断言成功应答并解出 CBOR：首字节必须是状态码 `CTAP2_OK`，其后才是 CBOR 载荷。
    fn decode_ok(resp: &[u8]) -> Value {
        assert_eq!(
            resp.first(),
            Some(&CTAP2_OK),
            "成功响应首字节必须是状态码 0x00: {resp:?}"
        );
        cbor::decode(&resp[1..])
            .unwrap_or_else(|err| panic!("成功响应必须是状态码 + CBOR: {err}; resp={resp:?}"))
            .0
    }

    /// 解析 makeCredential 应答，返回 (credential_id, COSE_Key)。
    fn create_credential(
        auth: &mut Authenticator<MemoryBackend>,
        rp_id: &str,
        user_handle: &[u8],
        seed: u8,
        rk: bool,
    ) -> (Vec<u8>, Value) {
        let request = make_credential_request_with_rk(rp_id, user_handle, &client_hash(seed), rk);
        let response =
            auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&request)].concat());
        let created = decode_ok(&response);
        let parsed =
            parse_auth_data(created.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.flags & FLAG_UV, FLAG_UV);
        assert_eq!(parsed.flags & FLAG_AT, FLAG_AT);
        (
            parsed.credential_id.unwrap().to_vec(),
            parsed.cose_key.unwrap(),
        )
    }

    /// 空 allowList 断言并校验选中项、user 实体、numberOfCredentials 与签名。
    fn assert_discoverable_selection(
        auth: &mut Authenticator<MemoryBackend>,
        expected_user: &[u8],
        expected_credential_id: &[u8],
        expected_count: usize,
        cose: &Value,
        seed: u8,
    ) {
        let hash = client_hash(seed);
        let request = get_assertion_request("example.com", &hash, None);
        let response =
            auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&request)].concat());
        let assertion = decode_ok(&response);

        let descriptor = assertion.get_int(1).expect("缺少 credential descriptor");
        assert_eq!(
            descriptor.get_text("id").and_then(Value::as_bytes),
            Some(expected_credential_id)
        );
        let user = assertion.get_int(4).expect("可发现路径必须返回 user 实体");
        assert_eq!(
            user.get_text("id").and_then(Value::as_bytes),
            Some(expected_user)
        );
        assert_eq!(
            assertion.get_int(5).and_then(Value::as_i64),
            Some(expected_count as i64)
        );

        let auth_data = assertion.get_int(2).and_then(Value::as_bytes).unwrap();
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.flags & FLAG_UV, FLAG_UV);
        assert_eq!(parsed.flags & FLAG_AT, 0, "GetAssertion 不得置 AT(0x40)");
        let signature = assertion.get_int(3).and_then(Value::as_bytes).unwrap();
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&hash);
        verify_cose_signature(cose, &message, signature).expect("DER 签名必须验证通过");
    }

    #[test]
    fn make_and_get_assertion_with_der_verify() {
        let backend = MemoryBackend::new();
        let mut auth = Authenticator::new(backend);
        let create = make_credential_request("example.com", b"user-1", &client_hash(7));
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        let created = decode_ok(&resp);
        assert_eq!(
            created.get_int(1).and_then(Value::as_text),
            Some("none"),
            "attestation fmt 必须是 none"
        );
        let auth_data = created.get_int(2).and_then(Value::as_bytes).unwrap();
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.rp_id_hash, crypto::sha256(b"example.com"));
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.flags & FLAG_UV, FLAG_UV);
        assert_eq!(parsed.flags & FLAG_AT, FLAG_AT);
        assert_eq!(parsed.sign_count, INITIAL_SIGN_COUNT);
        let cose = parsed.cose_key.clone().unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        let hash2 = client_hash(9);
        let get = get_assertion_request("example.com", &hash2, Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        let assertion = decode_ok(&resp);
        let auth_data = assertion.get_int(2).and_then(Value::as_bytes).unwrap();
        let sig = assertion.get_int(3).and_then(Value::as_bytes).unwrap();
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.sign_count, 2);
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.flags & FLAG_UV, FLAG_UV);
        assert_eq!(parsed.flags & FLAG_AT, 0);
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
    /// 3=signature，5=numberOfCredentials；allowList 路径不得含 4=user。
    /// 1/2 互换会被判 kCtap2ErrInvalidCBOR。
    #[test]
    fn get_assertion_response_follows_ctap21_key_layout() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let user_handle = b"user-regress".to_vec();
        let create = make_credential_request("example.com", &user_handle, &client_hash(3));
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        let created = decode_ok(&resp);
        let parsed =
            parse_auth_data(created.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        let cose = parsed.cose_key.clone().unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        let hash = client_hash(4);
        let get = get_assertion_request("example.com", &hash, Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        let assertion = decode_ok(&resp);

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
        let parsed = parse_auth_data(auth_data).unwrap();
        assert_eq!(parsed.flags & FLAG_UP, FLAG_UP);
        assert_eq!(parsed.flags & FLAG_UV, FLAG_UV);
        assert_eq!(parsed.flags & FLAG_AT, 0, "GetAssertion 不得置 AT(0x40)");

        // key3 必须是 DER 签名，且能对 authData ‖ clientHash 验签。
        let sig = assertion
            .get_int(3)
            .and_then(Value::as_bytes)
            .expect("key3 必须是 signature bytes");
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&hash);
        verify_cose_signature(&cose, &msg, sig).expect("DER 签名必须验证通过");

        // key4 不得出现：allowList 路径不返回 user；只有空 allowList 的可发现路径才返回
        // （见 discoverable 相关测试）。
        assert!(
            assertion.get_int(4).is_none(),
            "allowList 路径不得带 user 实体（key 4）"
        );

        // key5 numberOfCredentials：allowList 路径为匹配数，这里是 1。
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
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        decode_ok(&resp);

        let get = get_assertion_request("b.example", &client_hash(2), None);
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);

        let get = get_assertion_request("a.example", &client_hash(2), Some(b"unknown"));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);

        // 普通（非 discoverable）凭据不会被空 allowList 选中。
        let get = get_assertion_request("a.example", &client_hash(2), None);
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);
    }

    #[test]
    fn multiple_credentials_select_by_allow_list() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        // 第一颗
        let req1 = make_credential_request("example.com", b"u1", &client_hash(1));
        let resp1 = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req1)].concat());
        decode_ok(&resp1);
        let req2 = make_credential_request("example.com", b"u2", &client_hash(2));
        let resp2 = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req2)].concat());
        let created2 = decode_ok(&resp2);
        let parsed2 =
            parse_auth_data(created2.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        let id2 = parsed2.credential_id.unwrap().to_vec();

        let get = get_assertion_request("example.com", &client_hash(3), Some(&id2));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        let assertion = decode_ok(&resp);
        let descriptor = assertion.get_int(1).unwrap();
        assert_eq!(
            descriptor.get_text("id").and_then(Value::as_bytes),
            Some(&id2[..]),
            "必须选中 allowList 指定的凭据"
        );
    }

    #[test]
    fn get_info_declares_rk_up_uv_without_plat_or_client_pin() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let resp = auth.handle_cbor(&[CTAP2_GET_INFO]);
        let info = decode_ok(&resp);
        assert!(matches!(info.get_int(1), Some(Value::Array(_))));
        assert!(info.get_int(6).is_none(), "不能声明 clientPin");
        let options = info.get_int(4).expect("缺少 options");
        assert_eq!(options.get_text("rk").and_then(Value::as_bool), Some(true));
        assert_eq!(options.get_text("up").and_then(Value::as_bool), Some(true));
        assert_eq!(options.get_text("uv").and_then(Value::as_bool), Some(true));
        assert!(options.get_text("plat").is_none(), "不能声明 plat");
        assert!(
            options.get_text("clientPin").is_none(),
            "不能声明 clientPin"
        );
    }

    #[test]
    fn rk_registration_is_stored_as_discoverable() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (cred_id, _) = create_credential(&mut auth, "example.com", b"rk-user", 1, true);
        let discoverable = auth.backend().find("example.com", None, true).unwrap();
        assert_eq!(discoverable.len(), 1);
        assert_eq!(discoverable[0].credential_id, cred_id);
        assert_eq!(discoverable[0].user_handle.as_slice(), b"rk-user");
        assert!(discoverable[0].discoverable);
    }

    #[test]
    fn non_rk_registration_is_not_discoverable() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (cred_id, _) = create_credential(&mut auth, "example.com", b"plain", 1, false);
        assert!(
            auth.backend()
                .find("example.com", None, true)
                .unwrap()
                .is_empty(),
            "未请求 rk 的凭据不得进入可发现集合"
        );
        let ids = vec![cred_id];
        assert_eq!(
            auth.backend()
                .find("example.com", Some(&ids), false)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn empty_allow_list_selects_discoverable_and_returns_user_and_count() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (cred_id, cose) = create_credential(&mut auth, "example.com", b"user-rk", 1, true);
        assert_discoverable_selection(&mut auth, b"user-rk", &cred_id, 1, &cose, 2);
    }

    #[test]
    fn empty_allow_list_without_discoverable_returns_2e() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        create_credential(&mut auth, "example.com", b"plain", 1, false);
        let get = get_assertion_request("example.com", &client_hash(2), None);
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_NO_CREDENTIALS]);
    }

    #[test]
    fn allow_list_path_does_not_return_user() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (cred_id, _) = create_credential(&mut auth, "example.com", b"user-rk", 1, true);
        let get = get_assertion_request("example.com", &client_hash(2), Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        let assertion = decode_ok(&resp);
        assert!(
            assertion.get_int(4).is_none(),
            "allowList 路径不得返回 user 实体"
        );
        assert_eq!(assertion.get_int(5).and_then(Value::as_i64), Some(1));
    }

    #[test]
    fn exclude_list_returns_credential_excluded() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (cred_id, _) = create_credential(&mut auth, "example.com", b"user-1", 1, false);

        let mut req =
            make_credential_request_with_rk("example.com", b"user-2", &client_hash(2), true);
        if let Value::Map(entries) = &mut req {
            entries.push((
                Value::UInt(5),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(cred_id)),
                ])]),
            ));
        }
        let resp = auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&req)].concat());
        assert_eq!(resp, vec![CTAP2_ERR_CREDENTIAL_EXCLUDED]);
    }

    #[test]
    fn make_credential_and_get_assertion_flags_are_exact_bytes() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let request = make_credential_request("example.com", b"flags-user", &client_hash(1));
        let resp =
            auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&request)].concat());
        let created = decode_ok(&resp);
        let make_credential_auth_data = created.get_int(2).and_then(Value::as_bytes).unwrap();
        assert_eq!(
            make_credential_auth_data[32], 0x45,
            "MakeCredential flags 必须是 UP|UV|AT(0x40)"
        );
        let parsed = parse_auth_data(make_credential_auth_data).unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        let get = get_assertion_request("example.com", &client_hash(2), Some(&cred_id));
        let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        let assertion = decode_ok(&resp);
        let get_assertion_auth_data = assertion.get_int(2).and_then(Value::as_bytes).unwrap();
        assert_eq!(
            get_assertion_auth_data[32], 0x05,
            "GetAssertion flags 必须是 UP|UV（0x40 是 AT，不是 rk）"
        );
    }

    #[test]
    fn discoverable_selection_prefers_highest_sign_count_then_first() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let (id_a, cose_a) = create_credential(&mut auth, "example.com", b"user-a", 1, true);
        let (id_b, cose_b) = create_credential(&mut auth, "example.com", b"user-b", 2, true);

        // 初始 sign_count 都是 1：平手取后端顺序第一个 A（断言后 A: 1 -> 2）。
        assert_discoverable_selection(&mut auth, b"user-a", &id_a, 2, &cose_a, 3);

        // 用 allowList 断言 B 两次，把 B 的 sign_count 提到 3，超过 A 的 2。
        for seed in [4u8, 5u8] {
            let get = get_assertion_request("example.com", &client_hash(seed), Some(&id_b));
            let resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
            decode_ok(&resp);
        }

        // 现在 B 的 sign_count 最大：空 allowList 必须选 B。
        assert_discoverable_selection(&mut auth, b"user-b", &id_b, 2, &cose_b, 6);
    }

    #[test]
    fn authenticator_selection_returns_single_ok_byte() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let req = Value::Map(vec![(Value::UInt(1), Value::Text("example.com".into()))]);
        let resp =
            auth.handle_cbor(&[vec![CTAP2_AUTHENTICATOR_SELECTION], cbor::encode(&req)].concat());
        // 内部载荷为空，边界补状态字节后为单字节 `CTAP2_OK`。
        assert_eq!(
            resp,
            vec![CTAP2_OK],
            "authenticatorSelection 成功应答必须是单字节 0x00: {resp:?}"
        );
    }

    /// 回归：CTAP2 成功响应**必须**带前导状态字节 `0x00`。
    ///
    /// 依据：Chromium 的 CTAPHID 层把响应首字节当状态码读取，去掉 `0x00` 后
    /// Chrome 报 `GetInfo CTAP2 error code 166`——`166 = 0xA6` 正是 CBOR
    /// map(6) 的首字节，即它把 CBOR 头误当成了状态码（Fedora 实测）。
    #[test]
    fn success_responses_start_with_ok_status_byte() {
        let mut auth = Authenticator::new(MemoryBackend::new());

        // getInfo。
        let info_resp = auth.handle_cbor(&[CTAP2_GET_INFO]);
        assert_eq!(info_resp[0], CTAP2_OK, "getInfo 应答必须带前导 0x00");
        assert!(
            matches!(cbor::decode(&info_resp[1..]).unwrap().0, Value::Map(_)),
            "getInfo 状态字节之后必须是 CBOR map"
        );

        // makeCredential。
        let user_handle = b"regress-user".to_vec();
        let create = make_credential_request("example.com", &user_handle, &client_hash(1));
        let create_resp =
            auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&create)].concat());
        assert_eq!(
            create_resp[0], CTAP2_OK,
            "makeCredential 应答必须带前导 0x00"
        );
        let created = cbor::decode(&create_resp[1..]).unwrap().0;
        assert!(matches!(created, Value::Map(_)));
        let parsed =
            parse_auth_data(created.get_int(2).and_then(Value::as_bytes).unwrap()).unwrap();
        let cred_id = parsed.credential_id.unwrap().to_vec();

        // getAssertion。
        let get = get_assertion_request("example.com", &client_hash(2), Some(&cred_id));
        let get_resp = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&get)].concat());
        assert_eq!(get_resp[0], CTAP2_OK, "getAssertion 应答必须带前导 0x00");
        assert!(matches!(
            cbor::decode(&get_resp[1..]).unwrap().0,
            Value::Map(_)
        ));
    }

    #[test]
    fn invalid_cbor_is_single_byte_error() {
        let mut auth = Authenticator::new(MemoryBackend::new());
        let resp = auth.handle_cbor(&[CTAP2_GET_ASSERTION, 0xFF]);
        assert_eq!(resp, vec![CTAP2_ERR_INVALID_CBOR]);
        assert_eq!(resp.len(), 1);
    }

    /// 调试摘要：makeCredential 必须带上 rp_id 与 rk，且 alg 来自 pubKeyCredParams。
    #[test]
    fn request_detail_make_credential_reports_rp_and_rk() {
        let request =
            make_credential_request_with_rk("example.com", b"user-detail", &client_hash(1), true);
        let line = request_detail_line(CTAP2_MAKE_CREDENTIAL, &request);
        assert!(line.contains("cmd=0x01"), "{line}");
        assert!(line.contains("rp_id=example.com"), "{line}");
        assert!(line.contains("rk=true"), "{line}");
        assert!(line.contains("alg=-7"), "{line}");
        assert!(line.contains("attestation=none"), "{line}");
    }

    /// 调试摘要：getAssertion 必须带上 rp_id 与 allowList 长度。
    #[test]
    fn request_detail_get_assertion_reports_rp_and_allow() {
        let request = get_assertion_request("example.com", &client_hash(1), Some(b"cred-1"));
        let line = request_detail_line(CTAP2_GET_ASSERTION, &request);
        assert!(line.contains("cmd=0x02"), "{line}");
        assert!(line.contains("rp_id=example.com"), "{line}");
        assert!(line.contains("allow=1"), "{line}");

        let empty_allow = get_assertion_request("example.com", &client_hash(1), None);
        let line = request_detail_line(CTAP2_GET_ASSERTION, &empty_allow);
        assert!(line.contains("allow=empty"), "{line}");
    }

    /// 调试摘要：字段解析失败只输出 parse=failed，不 panic。
    #[test]
    fn request_detail_unparsable_reports_parse_failed() {
        let request = Value::Map(vec![(Value::UInt(99), Value::Text("x".into()))]);
        assert_eq!(
            request_detail_line(CTAP2_GET_ASSERTION, &request),
            "CTAP req-detail parse=failed"
        );
        assert_eq!(
            request_detail_line(CTAP2_MAKE_CREDENTIAL, &request),
            "CTAP req-detail parse=failed"
        );
    }
}
