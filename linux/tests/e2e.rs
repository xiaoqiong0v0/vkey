//! 端到端测试：本地启动 `vkeyd`（Go），两台设备 login/pair/sync。
//!
//! 覆盖：
//! 1. `vkey-hid login` → 写 TOTP 条目 → `selftest`（makeCredential/getAssertion）
//! 2. `pair-new` 生成配对码 → 第二台设备 `pair` → `sync` → 解密 → 验签

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use vkey_hid::api::{ApiClient, Auth};
use vkey_hid::config;
use vkey_hid::crypto;
use vkey_hid::ctap2::authenticator::{
    self, get_assertion_request, Authenticator, CTAP2_GET_ASSERTION,
};
use vkey_hid::ctap2::cbor;
use vkey_hid::policy;
use vkey_hid::store::{self, LocalStore, StoreBackend};
use vkey_hid::sync;
use zeroize::Zeroizing;

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("linux/ 的父目录")
        .to_path_buf()
}

fn scratch_root() -> PathBuf {
    let dir = repo_root().join(".tmp/scratch");
    fs::create_dir_all(&dir).expect("创建 .tmp/scratch");
    dir
}

fn unique_dir() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = scratch_root().join(format!("linux-e2e-{}-{}", std::process::id(), stamp));
    fs::create_dir_all(&dir).expect("创建 e2e 目录");
    dir
}

static VKEYD: OnceLock<PathBuf> = OnceLock::new();

fn build_vkeyd() -> Result<PathBuf> {
    if let Some(path) = VKEYD.get() {
        return Ok(path.clone());
    }
    let out = scratch_root().join(if cfg!(windows) {
        "e2e-vkeyd.exe"
    } else {
        "e2e-vkeyd"
    });
    let server_dir = repo_root().join("server");
    let output = Command::new("go")
        .args(["build", "-o"])
        .arg(&out)
        .arg("./cmd/vkeyd")
        .current_dir(&server_dir)
        .output()
        .context("执行 go build 失败（go 是否在 PATH？）")?;
    if !output.status.success() {
        bail!(
            "go build ./cmd/vkeyd 失败:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = VKEYD.set(out.clone());
    Ok(out)
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn init_db(vkeyd: &Path, db: &Path) -> Result<String> {
    let output = Command::new(vkeyd)
        .arg("init")
        .arg("--db")
        .arg(db)
        .output()
        .context("执行 vkeyd init 失败")?;
    if !output.status.success() {
        bail!(
            "vkeyd init 失败:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("master_key: "))
        .ok_or_else(|| anyhow!("init 未输出 master_key: {stdout}"))?;
    Ok(line.trim_start_matches("master_key: ").trim().to_string())
}

fn start_server(vkeyd: &Path, db: &Path, port: u16) -> Result<ServerGuard> {
    let child = Command::new(vkeyd)
        .arg("serve")
        .arg("--db")
        .arg(db)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("启动 vkeyd serve 失败")?;
    let guard = ServerGuard { child };
    let client = ApiClient::new(&format!("http://127.0.0.1:{port}"))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if client.health().is_ok() {
            return Ok(guard);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("vkeyd 在 15 秒内未就绪（端口 {port}）");
}

fn run_cli(dir: &Path, args: &[String]) -> Output {
    let exe = env!("CARGO_BIN_EXE_vkey-hid");
    Command::new(exe)
        .env("VKEY_DATA_DIR", dir)
        .args(args)
        .output()
        .expect("执行 vkey-hid 失败")
}

fn assert_cli(dir: &Path, args: &[String]) -> String {
    let output = run_cli(dir, args);
    if !output.status.success() {
        panic!(
            "vkey-hid {:?} 失败（dir={}）：\nstdout:\n{}\nstderr:\n{}",
            args,
            dir.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn parse_pair_code(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        let parts: Vec<&str> = line.split('-').collect();
        if parts.len() >= 2
            && parts.iter().all(|p| {
                p.len() == 4
                    && p.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            })
        {
            Some(line.to_string())
        } else {
            None
        }
    })
}

fn unlock_local(dir: &Path, identity: &store::Identity) -> Result<Zeroizing<Vec<u8>>> {
    let local_key = store::read_local_key(dir)?;
    let blob = identity.local_wrapped_bytes()?;
    store::unwrap_master_local(&local_key, &blob)
}

#[test]
fn two_devices_share_credentials() -> Result<()> {
    let root = unique_dir();
    let vkeyd = build_vkeyd()?;
    let db = root.join("vkeyd.db");
    let master_key_b32 = init_db(&vkeyd, &db)?;
    let port = free_port()?;
    let _server = start_server(&vkeyd, &db, port)?;
    let url = format!("http://127.0.0.1:{port}");
    let client = ApiClient::new(&url)?;
    let master_key = Zeroizing::new(crypto::parse_master_key(&master_key_b32)?);

    // ---- 设备 A：login ----
    let a_dir = root.join("deviceA");
    let out = assert_cli(
        &a_dir,
        &[
            "login".into(),
            "--server".into(),
            url.clone(),
            "--master-key".into(),
            master_key_b32.clone(),
            "--device-name".into(),
            "desk-linux".into(),
        ],
    );
    assert!(out.contains("已登录"), "login 输出异常:\n{out}");
    let a_identity = store::load_identity(&a_dir)?;
    assert_eq!(a_identity.username, "default");

    // ---- A 写一条 TOTP 条目并同步 ----
    let mut a_store = LocalStore::load(&a_dir, master_key.clone())?;
    let totp_id = store::new_item_id()?;
    let totp = json!({
        "kind": "totp",
        "label": "e2e@example.com",
        "issuer": "E2E",
        "secret": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "created_at": config::now_unix(),
    });
    a_store.upsert_plaintext(
        totp_id.clone(),
        "totp".into(),
        "example.com".into(),
        totp.clone(),
        0,
        0,
        config::now_unix(),
    )?;
    a_store.save()?;
    let a_auth = Auth::from_encoded(&a_identity.ed25519_seed, &a_identity.token)?;
    let (a_store, report) = sync::sync_once(&client, &a_auth, a_store)?;
    assert!(report.pushed >= 1, "TOTP 条目未推送: {report:?}");
    assert_eq!(a_store.get(&totp_id).map(|i| i.version), Some(1));
    drop(a_store);

    // ---- A selftest（makeCredential + getAssertion + 同步） ----
    let selftest_out = assert_cli(&a_dir, &["selftest".into()]);
    assert!(
        selftest_out.contains("SELFTEST PASS"),
        "selftest 未通过:\n{selftest_out}"
    );
    assert!(
        selftest_out.contains("[2/6] MakeCredential"),
        "selftest 输出缺少 MakeCredential 步骤:\n{selftest_out}"
    );

    // A 本地应同时有 TOTP 与 WebAuthn 条目，且 WebAuthn sign_count 已到 2。
    let a_after = LocalStore::load(&a_dir, unlock_local(&a_dir, &a_identity)?)?;
    assert!(a_after.item_count() >= 2, "A 条目数不足");
    let web = a_after
        .items()
        .find(|i| i.kind == "webauthn")
        .ok_or_else(|| anyhow!("A 缺少 webauthn 条目"))?;
    let web_value = web
        .plaintext
        .as_ref()
        .ok_or_else(|| anyhow!("A webauthn 条目未解密"))?;
    assert_eq!(
        web_value.get("sign_count").and_then(|v| v.as_u64()),
        Some(2)
    );

    // ---- A 生成配对码 ----
    let pair_out = assert_cli(&a_dir, &["pair-new".into()]);
    let code = parse_pair_code(&pair_out)
        .ok_or_else(|| anyhow!("无法从 pair-new 输出解析配对码:\n{pair_out}"))?;

    // ---- 设备 B：pair + sync ----
    let b_dir = root.join("deviceB");
    let b_out = assert_cli(
        &b_dir,
        &[
            "pair".into(),
            "--server".into(),
            url.clone(),
            "--code".into(),
            code.clone(),
            "--device-name".into(),
            "phone".into(),
        ],
    );
    assert!(b_out.contains("配对成功"), "pair 输出异常:\n{b_out}");
    let sync_out = assert_cli(&b_dir, &["sync".into()]);
    assert!(sync_out.contains("pulled="), "sync 输出异常:\n{sync_out}");

    // ---- B 解密并验签 ----
    let b_identity = store::load_identity(&b_dir)?;
    let b_master = unlock_local(&b_dir, &b_identity)?;
    let b_store = LocalStore::load(&b_dir, b_master)?;
    assert!(
        b_store.item_count() >= 2,
        "B 拉取条目不足: {}",
        b_store.item_count()
    );

    let b_totp = b_store
        .items()
        .find(|i| i.id == totp_id)
        .ok_or_else(|| anyhow!("B 未拉取到 TOTP 条目"))?;
    let b_totp_value = b_totp.plaintext.as_ref().unwrap();
    assert_eq!(
        b_totp_value.get("secret").and_then(|v| v.as_str()),
        Some("JBSWY3DPEHPK3PXP")
    );
    assert_eq!(
        b_totp_value.get("issuer").and_then(|v| v.as_str()),
        Some("E2E")
    );

    let b_web = b_store
        .items()
        .find(|i| i.kind == "webauthn")
        .ok_or_else(|| anyhow!("B 未拉取到 webauthn 条目"))?;
    let value = b_web.plaintext.as_ref().unwrap().clone();
    let rp_id = value
        .get("rp_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("webauthn 条目缺少 rp_id"))?
        .to_string();
    let credential_id = crypto::b64_decode(
        value
            .get("credential_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("缺少 credential_id"))?,
    )?;
    let private_key_der = crypto::b64_decode(
        value
            .get("private_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("缺少 private_key"))?,
    )?;

    // B 用同步下来的私钥实际生成一次断言，并用 COSE 公钥验签。
    let shared = std::sync::Arc::new(std::sync::Mutex::new(b_store));
    let backend = StoreBackend::new(shared, sync::noop_trigger());
    let mut authenticator = Authenticator::new(backend);
    let client_hash = crypto::random_bytes(32)?;
    let request = get_assertion_request(&rp_id, &client_hash, Some(&credential_id));
    let response =
        authenticator.handle_cbor(&[vec![CTAP2_GET_ASSERTION], cbor::encode(&request)].concat());
    assert_eq!(response[0], 0, "B getAssertion 失败: {response:?}");
    let (assertion, _) = cbor::decode(&response[1..])?;
    // authData 在 key2（Chromium 读取顺序，见 docs/evidence/device_response_converter.cc:242-249）。
    let auth_data = assertion
        .get_int(2)
        .and_then(cbor::Value::as_bytes)
        .ok_or_else(|| anyhow!("断言缺少 authData"))?;
    let signature = assertion
        .get_int(3)
        .and_then(cbor::Value::as_bytes)
        .ok_or_else(|| anyhow!("断言缺少 signature"))?;
    let cose = authenticator::cose_key_from_pkcs8(&private_key_der)?;
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&client_hash);
    authenticator::verify_cose_signature(&cose, &message, signature)
        .context("B 用同步私钥生成的断言验签失败")?;

    // ---- status ----
    let status_out = assert_cli(&a_dir, &["status".into()]);
    assert!(status_out.contains("policy:      require_master_pw=false"));
    assert!(status_out.contains("unlocked:    true"));
    assert!(status_out.contains("items:"));

    println!("e2e 数据目录：{}", root.display());
    Ok(())
}

/// 用 `vkeyd policy set` 修改服务端策略（独立进程写同一个 WAL 库）。
fn set_require_master_pw(vkeyd: &Path, db: &Path, require: bool) -> Result<()> {
    let output = Command::new(vkeyd)
        .arg("policy")
        .arg("set")
        .arg("--db")
        .arg(db)
        .arg(format!("--require-master-pw={require}"))
        .output()
        .context("执行 vkeyd policy set 失败")?;
    if !output.status.success() {
        bail!(
            "vkeyd policy set 失败:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// 主密码端到端流程（与 `vkey-hid passwd` 的库级步骤等价）。
///
/// CLI 的密码输入走 rpassword/systemd-ask-password，无法在自动化测试中喂 stdin，
/// 因此这里直接调用 `passwd` 使用的同一组库函数，并模拟「重启后」从磁盘重载身份。
#[test]
fn master_password_flow() -> Result<()> {
    const PASSWORD: &str = "correct horse battery staple";
    let root = unique_dir();
    let vkeyd = build_vkeyd()?;
    let db = root.join("vkeyd.db");
    let master_key_b32 = init_db(&vkeyd, &db)?;
    let port = free_port()?;
    let _server = start_server(&vkeyd, &db, port)?;
    let url = format!("http://127.0.0.1:{port}");
    let client = ApiClient::new(&url)?;
    let master_key = Zeroizing::new(crypto::parse_master_key(&master_key_b32)?);

    let a_dir = root.join("deviceA");
    assert_cli(
        &a_dir,
        &[
            "login".into(),
            "--server".into(),
            url.clone(),
            "--master-key".into(),
            master_key_b32.clone(),
            "--device-name".into(),
            "desk-linux".into(),
        ],
    );
    let identity = store::load_identity(&a_dir)?;

    // ---- 分支 2：require=true 但服务端无包裹 → 明确要求先 passwd ----
    set_require_master_pw(&vkeyd, &db, true)?;
    let policy_required = policy::fetch_and_resolve(&a_dir, || client.policy())?;
    assert!(policy_required.require_master_pw);
    assert!(!policy_required.require_master_pw_enforced);

    let err = store::unlock_by_policy(&a_dir, &identity, &policy_required, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("vkey-hid passwd"),
        "enforced=false 时应提示 passwd: {err:#}"
    );
    // 真实启动路径（sync）也必须拒绝，而不是静默用 local.key。
    let sync_out = run_cli(&a_dir, &["sync".into()]);
    assert!(
        !sync_out.status.success(),
        "enforced=false 时 sync 不应成功"
    );
    let sync_err = String::from_utf8_lossy(&sync_out.stderr);
    assert!(
        sync_err.contains("vkey-hid passwd"),
        "sync 错误信息未提示 passwd:\n{sync_err}"
    );

    // ---- passwd 的库级步骤：包裹 master_key 并上传 ----
    let salt = store::new_pw_salt()?;
    let wrapped = store::wrap_master_password(&master_key, PASSWORD, &salt, &policy_required)?;
    let auth = Auth::from_encoded(&identity.ed25519_seed, &identity.token)?;
    client.set_password(
        &auth,
        &crypto::b64_encode(&salt),
        &crypto::b64_encode(&wrapped),
    )?;

    let policy_enforced = policy::fetch_and_resolve(&a_dir, || client.policy())?;
    assert!(policy_enforced.require_master_pw);
    assert!(
        policy_enforced.require_master_pw_enforced,
        "写入包裹后 enforced 必须为 true"
    );

    // ---- 模拟重启：把 pw_salt/wrapped_key 落盘后重新加载 identity ----
    let mut updated = identity.clone();
    updated.pw_salt = Some(crypto::b64_encode(&salt));
    updated.wrapped_master_key = crypto::b64_encode(&wrapped);
    store::save_identity(&a_dir, &updated)?;
    let reloaded = store::load_identity(&a_dir)?;
    assert!(reloaded.has_pw_wrap());

    // ---- 分支 1：错误密码拒绝 / 正确密码通过 ----
    let wrong =
        store::unlock_by_policy(&a_dir, &reloaded, &policy_enforced, Some("wrong password"));
    assert!(wrong.is_err(), "错误主密码不应解出 master_key");
    let unlocked = store::unlock_by_policy(&a_dir, &reloaded, &policy_enforced, Some(PASSWORD))?;
    assert!(
        crypto::equal_ct(&unlocked, &master_key),
        "正确主密码解出的 master_key 不一致"
    );

    // ---- passwd --clear 的服务端部分 ----
    client.clear_password(&auth)?;
    let policy_cleared = policy::fetch_and_resolve(&a_dir, || client.policy())?;
    assert!(policy_cleared.require_master_pw);
    assert!(!policy_cleared.require_master_pw_enforced);
    assert!(
        store::unlock_by_policy(&a_dir, &reloaded, &policy_cleared, Some(PASSWORD)).is_err(),
        "清除包裹后 require=true/enforced=false 必须拒绝启动"
    );

    // ---- 分支 3：策略关闭后回到 local.key ----
    set_require_master_pw(&vkeyd, &db, false)?;
    let policy_off = policy::fetch_and_resolve(&a_dir, || client.policy())?;
    let local = store::unlock_by_policy(&a_dir, &reloaded, &policy_off, None)?;
    assert!(crypto::equal_ct(&local, &master_key));

    println!("主密码流程数据目录：{}", root.display());
    Ok(())
}
