//! `vkey-hid selftest`：无 uhid 情况下跑完整 CTAP2 回归。
//!
//! 覆盖 GetInfo / MakeCredential / GetAssertion / DER 验签 / CTAPHID 大包分片；
//! 有本地身份时使用真实加密存储（并在末尾尝试同步），否则使用内存后端。

use anyhow::{anyhow, bail, Context, Result};
use std::sync::{Arc, Mutex};
use vkey_hid::api::ApiClient;
use vkey_hid::config;
use vkey_hid::crypto;
use vkey_hid::ctap2::authenticator::{
    self, parse_auth_data, Authenticator, CredentialBackend, MemoryBackend, CTAP2_GET_ASSERTION,
    CTAP2_GET_INFO, CTAP2_MAKE_CREDENTIAL, CTAP2_OK, FLAG_AT_PUBLIC, FLAG_UP, FLAG_UV,
};
use vkey_hid::ctap2::cbor::{self, Value};
use vkey_hid::ctap2::hid::{Ctap2Handler, CtapHid, CTAPHID_CBOR};
use vkey_hid::policy;
use vkey_hid::store::{self, Identity, LocalStore, StoreBackend};
use vkey_hid::sync;
use zeroize::Zeroizing;

const RP_ID: &str = "selftest.invalid";
const USER_HANDLE: &[u8] = b"vkey-selftest-user";
const RK_USER_HANDLE: &[u8] = b"vkey-selftest-rk-user";

struct Runner {
    index: usize,
    total: usize,
    ok: bool,
}

impl Runner {
    fn new(total: usize) -> Self {
        Self {
            index: 0,
            total,
            ok: true,
        }
    }

    fn check(&mut self, name: &str, result: Result<()>) -> bool {
        self.index += 1;
        match result {
            Ok(()) => {
                println!("[{}/{}] {name} ... PASS", self.index, self.total);
                true
            }
            Err(err) => {
                self.ok = false;
                println!("[{}/{}] {name} ... FAIL: {err:#}", self.index, self.total);
                false
            }
        }
    }
}

/// 执行 selftest；返回 false 表示有检查失败。
pub fn run() -> Result<bool> {
    let dir = config::data_dir()?;
    match store::load_identity(&dir) {
        Ok(identity) => run_with_identity(&dir, &identity),
        Err(_) => run_ephemeral(),
    }
}

fn run_ephemeral() -> Result<bool> {
    println!("vkey-hid selftest（未找到本地身份：使用内存后端，不落盘、不同步）");
    let mut auth = Authenticator::new(MemoryBackend::new());
    let mut runner = Runner::new(7);
    let ok = suite(&mut auth, &mut runner)?;
    println!("SELFTEST {}", if ok && runner.ok { "PASS" } else { "FAIL" });
    Ok(ok && runner.ok)
}

fn run_with_identity(dir: &std::path::Path, identity: &Identity) -> Result<bool> {
    println!("vkey-hid selftest（数据目录 {}）", dir.display());
    let client = ApiClient::new(&identity.server_url)?;

    // 策略：服务端可达用服务端，不可达用缓存；都没有时失败关闭（不绕过主密码策略）。
    let policy = policy::fetch_and_resolve(dir, || client.policy())?;
    let master_key = unlock(dir, identity, &policy)?;

    let store = LocalStore::load(dir, master_key.clone())?;
    let shared_store = Arc::new(Mutex::new(store));
    let backend = StoreBackend::new(shared_store.clone(), sync::noop_trigger());
    let mut auth = Authenticator::new(backend);
    let mut runner = Runner::new(8);
    let suite_ok = suite(&mut auth, &mut runner)?;

    // 从后端取回本地存储，检查落盘内容只含密文。
    let backend = auth.into_backend();
    let shared = backend.shared().clone();
    drop(backend);
    drop(shared_store);
    runner.check(
        "条目缓存落盘为密文（无 private_key 明文）",
        check_items_encrypted(dir, &master_key),
    );

    let ok = suite_ok && runner.ok;
    if ok {
        match sync_after(dir, identity, shared) {
            Ok(report) => println!(
                "sync: pushed={} pulled={} conflicts={} seq={}",
                report.pushed, report.pulled, report.conflicts, report.seq
            ),
            Err(err) => eprintln!("vkey-hid: selftest 同步失败（不影响本地 PASS）: {err:#}"),
        }
    }

    println!("SELFTEST {}", if ok && runner.ok { "PASS" } else { "FAIL" });
    Ok(ok && runner.ok)
}

fn sync_after(
    dir: &std::path::Path,
    identity: &Identity,
    shared: Arc<Mutex<LocalStore>>,
) -> Result<sync::SyncReport> {
    let _ = dir;
    let client = ApiClient::new(&identity.server_url)?;
    let seed = crypto::b64_decode(&identity.ed25519_seed).context("ed25519_seed 解码失败")?;
    let token = crypto::b64_decode(&identity.token).context("token 解码失败")?;
    let auth = vkey_hid::api::Auth::new(&seed, token)?;
    let store = Arc::try_unwrap(shared)
        .map_err(|_| anyhow!("selftest 后仍存在本地存储引用"))?
        .into_inner()
        .map_err(|_| anyhow!("本地存储锁中毒"))?;
    let (_store, report) = sync::sync_once(&client, &auth, store)?;
    Ok(report)
}

fn unlock(
    dir: &std::path::Path,
    identity: &Identity,
    policy: &policy::EffectivePolicy,
) -> Result<Zeroizing<Vec<u8>>> {
    policy::ensure_unlockable(policy, identity.has_pw_wrap())?;
    if policy.require_master_pw_enforced {
        let password = config::read_password("vkey 主密码: ")?;
        return store::unlock_by_policy(dir, identity, policy, Some(password.as_str()));
    }
    store::unlock_by_policy(dir, identity, policy, None)
}

fn check_items_encrypted(dir: &std::path::Path, master_key: &[u8]) -> Result<()> {
    let raw = std::fs::read(dir.join("items.json")).context("读取 items.json 失败")?;
    let text = String::from_utf8_lossy(&raw);
    if text.contains("private_key") || text.contains("JBSWY3DP") {
        bail!("items.json 中出现了明文私钥/密钥字段");
    }
    // 能重新加载并解密，说明密文与 master_key 匹配。
    let store = LocalStore::load(dir, Zeroizing::new(master_key.to_vec()))?;
    let webauthn = store
        .items()
        .filter(|i| i.kind == "webauthn" && i.rp_id == RP_ID)
        .count();
    if webauthn == 0 {
        bail!("items.json 中没有 selftest 创建的 webauthn 条目");
    }
    Ok(())
}

/// 核心 CTAP2 检查（存储无关）。
fn suite<B: CredentialBackend>(auth: &mut Authenticator<B>, runner: &mut Runner) -> Result<bool> {
    // 1) GetInfo
    let info_ok = runner.check(
        "GetInfo（versions 为 array、rk/up/uv、无 clientPin/plat）",
        check_get_info(auth),
    );
    if !info_ok {
        return Ok(false);
    }

    // 2) MakeCredential
    let client_hash_1 = crypto::random_bytes(32)?;
    let request = authenticator::make_credential_request(RP_ID, USER_HANDLE, &client_hash_1);
    let response =
        auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&request)].concat());
    let created = match check_make_credential(&response, &client_hash_1) {
        Ok(v) => v,
        Err(err) => {
            runner.check("MakeCredential（fmt=none / authData / COSE）", Err(err));
            return Ok(false);
        }
    };
    runner.check("MakeCredential（fmt=none / authData / COSE）", Ok(()));

    let auth_data = created
        .get_int(2)
        .and_then(Value::as_bytes)
        .unwrap()
        .to_vec();
    let parsed = parse_auth_data(&auth_data)?;
    let credential_id = parsed
        .credential_id
        .ok_or_else(|| anyhow!("MakeCredential authData 缺少 credentialId"))?
        .to_vec();
    let cose = parsed
        .cose_key
        .clone()
        .ok_or_else(|| anyhow!("MakeCredential authData 缺少 COSE_Key"))?;

    // 3) GetAssertion
    let client_hash_2 = crypto::random_bytes(32)?;
    let request = authenticator::get_assertion_request(RP_ID, &client_hash_2, Some(&credential_id));
    let response = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&request)].concat());
    let assertion = match check_get_assertion(&response, &client_hash_2, &credential_id, &cose) {
        Ok(v) => v,
        Err(err) => {
            runner.check("GetAssertion + DER 验签", Err(err));
            return Ok(false);
        }
    };
    runner.check("GetAssertion + DER 验签", Ok(()));

    // 4) 签名计数器 +1（authData 在 key2，见 docs/evidence/device_response_converter.cc:242-249）
    let assertion_auth_data = assertion.get_int(2).and_then(Value::as_bytes).unwrap();
    let count = parse_auth_data(assertion_auth_data)?.sign_count;
    runner.check(
        "签名计数器 +1（1 → 2）",
        if count == 2 {
            Ok(())
        } else {
            Err(anyhow!("signCount={count}，期望 2"))
        },
    );

    // 5) CTAPHID 7609B 分片/重组
    runner.check("CTAPHID 7609B 分片/重组", check_ctaphid_roundtrip());

    // 6) 可发现凭据注册（rk=true）
    let rk_client_hash = crypto::random_bytes(32)?;
    let rk_request = authenticator::make_credential_request_with_rk(
        RP_ID,
        RK_USER_HANDLE,
        &rk_client_hash,
        true,
    );
    let rk_response =
        auth.handle_cbor(&[vec![CTAP2_MAKE_CREDENTIAL], cbor::encode(&rk_request)].concat());
    let rk_ok = runner.check(
        "MakeCredential rk=true（discoverable + UP/UV/AT）",
        check_discoverable_registration(auth, &rk_response),
    );
    if !rk_ok {
        return Ok(false);
    }

    // 7) 无 allowList 的可发现断言（user 实体 + numberOfCredentials）
    let expected_discoverable = auth.backend().find(RP_ID, None, true)?.len();
    let assertion_hash = crypto::random_bytes(32)?;
    let request = authenticator::get_assertion_request(RP_ID, &assertion_hash, None);
    let response = auth.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&request)].concat());
    runner.check(
        "GetAssertion 无 allowList（user 实体 + numberOfCredentials）",
        check_discoverable_assertion(auth, &response, &assertion_hash, expected_discoverable),
    );

    Ok(runner.ok)
}

/// 解析 CTAP2 成功应答：首字节必须是 `CTAP2_OK`，其后才是 CBOR 载荷。
///
/// Chromium 的 CTAPHID 层把响应首字节当状态码读取，成功必须带 `0x00`；
/// 非 `0x00` 的单字节按错误状态处理。
fn decode_ok_response(response: &[u8]) -> Result<Value> {
    match response.first() {
        Some(&CTAP2_OK) => {}
        Some(&status) => bail!("CTAP2 错误状态 0x{status:02x}"),
        None => bail!("CTAP2 应答为空"),
    }
    let (value, _) = cbor::decode(&response[1..]).context("成功应答不是状态码 + CBOR")?;
    Ok(value)
}

fn check_get_info<B: CredentialBackend>(auth: &mut Authenticator<B>) -> Result<()> {
    let response = auth.handle_cbor(&[CTAP2_GET_INFO]);
    let info = decode_ok_response(&response)?;
    let versions = info
        .get_int(1)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("versions 不是 array"))?;
    if versions.is_empty() {
        bail!("versions 为空");
    }
    if info.get_int(6).is_some() {
        bail!("不应声明 clientPin");
    }
    let options = info.get_int(4).ok_or_else(|| anyhow!("缺少 options"))?;
    if options.get_text("up").and_then(Value::as_bool) != Some(true) {
        bail!("options.up 必须为 true");
    }
    if options.get_text("rk").and_then(Value::as_bool) != Some(true) {
        bail!("options.rk 必须为 true");
    }
    if options.get_text("uv").and_then(Value::as_bool) != Some(true) {
        bail!("options.uv 必须为 true");
    }
    if options.get_text("plat").is_some() {
        bail!("不应声明 plat");
    }
    Ok(())
}

fn check_make_credential(response: &[u8], _client_hash: &[u8]) -> Result<Value> {
    let value = decode_ok_response(response)?;
    if value.get_int(1).and_then(Value::as_text) != Some("none") {
        bail!("attestation fmt 不是 none");
    }
    let auth_data = value
        .get_int(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 authData"))?;
    let parsed = parse_auth_data(auth_data)?;
    if parsed.rp_id_hash != crypto::sha256(RP_ID.as_bytes()) {
        bail!("rpIdHash 不匹配");
    }
    if parsed.flags & FLAG_UP == 0 {
        bail!("MakeCredential flags 缺少 UP");
    }
    if parsed.flags & FLAG_UV == 0 {
        bail!("MakeCredential flags 缺少 UV");
    }
    if parsed.flags & FLAG_AT_PUBLIC == 0 {
        bail!("MakeCredential flags 缺少 AT");
    }
    if parsed.sign_count != 1 {
        bail!("初始 signCount 不是 1");
    }
    let cred_id = parsed
        .credential_id
        .ok_or_else(|| anyhow!("缺少 credentialId"))?;
    if cred_id.len() != 32 {
        bail!("credentialId 长度不是 32");
    }
    if parsed.cose_key.is_none() {
        bail!("缺少 COSE_Key");
    }
    Ok(value)
}

fn check_get_assertion(
    response: &[u8],
    client_hash: &[u8],
    credential_id: &[u8],
    cose: &Value,
) -> Result<Value> {
    let value = decode_ok_response(response)?;
    // 外层键位对齐 Chromium ReadCTAPGetAssertionResponse
    // （docs/evidence/device_response_converter.cc:242-274）：1=descriptor，2=authData。
    // descriptor 用文本键 "type"/"id"（.tmp/scratch/156_d.cc:16-17）。
    let descriptor = value
        .get_int(1)
        .ok_or_else(|| anyhow!("缺少 credential descriptor"))?;
    if descriptor.get_text("id").and_then(Value::as_bytes) != Some(credential_id) {
        bail!("返回的 credentialId 与请求不一致");
    }
    if descriptor.get_text("type").and_then(Value::as_text) != Some("public-key") {
        bail!("credential type 不是 public-key");
    }
    let auth_data = value
        .get_int(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 authData"))?;
    let signature = value
        .get_int(3)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 signature"))?;
    let parsed = parse_auth_data(auth_data)?;
    if parsed.flags & FLAG_UP == 0 {
        bail!("GetAssertion flags 缺少 UP");
    }
    if parsed.flags & FLAG_UV == 0 {
        bail!("GetAssertion flags 缺少 UV");
    }
    if parsed.flags & FLAG_AT_PUBLIC != 0 {
        bail!("GetAssertion authData 不应带 AT");
    }
    if parsed.rp_id_hash != crypto::sha256(RP_ID.as_bytes()) {
        bail!("GetAssertion rpIdHash 不匹配");
    }
    let mut message = auth_data.to_vec();
    message.extend_from_slice(client_hash);
    authenticator::verify_cose_signature(cose, &message, signature)
        .context("GetAssertion DER 验签失败")?;
    Ok(value)
}

fn check_discoverable_registration<B: CredentialBackend>(
    auth: &Authenticator<B>,
    response: &[u8],
) -> Result<()> {
    let value = decode_ok_response(response)?;
    let auth_data = value
        .get_int(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 authData"))?;
    let parsed = parse_auth_data(auth_data)?;
    if parsed.flags & FLAG_UP == 0 {
        bail!("rk 注册 flags 缺少 UP");
    }
    if parsed.flags & FLAG_UV == 0 {
        bail!("rk 注册 flags 缺少 UV");
    }
    if parsed.flags & FLAG_AT_PUBLIC == 0 {
        bail!("rk 注册 flags 缺少 AT");
    }
    let credential_id = parsed
        .credential_id
        .ok_or_else(|| anyhow!("rk 注册缺少 credentialId"))?;
    let discoverable = auth.backend().find(RP_ID, None, true)?;
    let found = discoverable
        .iter()
        .find(|cred| cred.credential_id.as_slice() == credential_id)
        .ok_or_else(|| anyhow!("rk=true 的凭据未以 discoverable 存入后端"))?;
    if !found.discoverable {
        bail!("条目 discoverable 字段不是 true");
    }
    if found.user_handle.as_slice() != RK_USER_HANDLE {
        bail!("discoverable 凭据的 user_handle 不匹配");
    }
    Ok(())
}

fn check_discoverable_assertion<B: CredentialBackend>(
    auth: &Authenticator<B>,
    response: &[u8],
    client_hash: &[u8],
    expected_count: usize,
) -> Result<()> {
    let value = decode_ok_response(response)?;
    let descriptor = value
        .get_int(1)
        .ok_or_else(|| anyhow!("缺少 credential descriptor"))?;
    if descriptor.get_text("type").and_then(Value::as_text) != Some("public-key") {
        bail!("credential type 不是 public-key");
    }
    let credential_id = descriptor
        .get_text("id")
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 credentialId"))?;
    let user = value
        .get_int(4)
        .ok_or_else(|| anyhow!("空 allowList 断言必须返回 user 实体"))?;
    let user_id = user
        .get_text("id")
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("user 实体缺少 id"))?;
    let number = value
        .get_int(5)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("缺少 numberOfCredentials"))?;
    if number < 0 || number as usize != expected_count {
        bail!("numberOfCredentials={number}，期望 {expected_count}");
    }
    let auth_data = value
        .get_int(2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 authData"))?;
    let signature = value
        .get_int(3)
        .and_then(Value::as_bytes)
        .ok_or_else(|| anyhow!("缺少 signature"))?;
    let parsed = parse_auth_data(auth_data)?;
    if parsed.flags & FLAG_UP == 0 {
        bail!("可发现断言 flags 缺少 UP");
    }
    if parsed.flags & FLAG_UV == 0 {
        bail!("可发现断言 flags 缺少 UV");
    }
    if parsed.flags & FLAG_AT_PUBLIC != 0 {
        bail!("GetAssertion authData 不得置 AT(0x40)");
    }
    if parsed.rp_id_hash != crypto::sha256(RP_ID.as_bytes()) {
        bail!("GetAssertion rpIdHash 不匹配");
    }
    let ids = vec![credential_id.to_vec()];
    let selected = auth
        .backend()
        .find(RP_ID, Some(&ids), true)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("返回的 credentialId 不是本地的可发现凭据"))?;
    if user_id != selected.user_handle.as_slice() {
        bail!("user 实体的 id 与选中凭据的 user_handle 不一致");
    }
    let cose = authenticator::cose_key_from_pkcs8(&selected.private_key_der)?;
    let mut message = auth_data.to_vec();
    message.extend_from_slice(client_hash);
    authenticator::verify_cose_signature(&cose, &message, signature)
        .context("可发现断言 DER 验签失败")?;
    Ok(())
}

fn check_ctaphid_roundtrip() -> Result<()> {
    struct NullHandler;
    impl Ctap2Handler for NullHandler {
        fn handle_cbor(&mut self, _payload: &[u8]) -> Vec<u8> {
            Vec::new()
        }
    }
    let payload: Vec<u8> = (0..7609).map(|i| (i % 251) as u8).collect();
    let frames = CtapHid::<NullHandler>::fragment(0x01020304, CTAPHID_CBOR, &payload);
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&frames[0][7..7 + 57]);
    for frame in &frames[1..] {
        rebuilt.extend_from_slice(&frame[5..5 + 59]);
    }
    rebuilt.truncate(payload.len());
    if rebuilt != payload {
        bail!("分片/重组结果不一致");
    }
    Ok(())
}
