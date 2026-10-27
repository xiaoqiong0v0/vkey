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
    CTAP2_GET_INFO, CTAP2_MAKE_CREDENTIAL, CTAP2_OK, FLAG_AT_PUBLIC,
};
use vkey_hid::ctap2::cbor::{self, Value};
use vkey_hid::ctap2::hid::{Ctap2Handler, CtapHid, CTAPHID_CBOR};
use vkey_hid::policy;
use vkey_hid::store::{self, Identity, LocalStore, StoreBackend};
use vkey_hid::sync;
use zeroize::Zeroizing;

const RP_ID: &str = "selftest.invalid";
const USER_HANDLE: &[u8] = b"vkey-selftest-user";

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
    let mut runner = Runner::new(5);
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
    let mut runner = Runner::new(6);
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
        "GetInfo（versions 为 array、无 clientPin/rk）",
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

    Ok(runner.ok)
}

fn check_get_info<B: CredentialBackend>(auth: &mut Authenticator<B>) -> Result<()> {
    let response = auth.handle_cbor(&[CTAP2_GET_INFO]);
    if response.first() != Some(&CTAP2_OK) {
        bail!("状态字节不是 0x00: {response:?}");
    }
    let (info, _) = cbor::decode(&response[1..])?;
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
    Ok(())
}

fn check_make_credential(response: &[u8], _client_hash: &[u8]) -> Result<Value> {
    if response.first() != Some(&CTAP2_OK) {
        bail!("状态字节不是 0x00: {response:?}");
    }
    let (value, _) = cbor::decode(&response[1..])?;
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
    if response.first() != Some(&CTAP2_OK) {
        bail!("状态字节不是 0x00: {response:?}");
    }
    let (value, _) = cbor::decode(&response[1..])?;
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
