//! vkey-hid CLI。
//!
//! 子命令：login / pair / run / status / sync / selftest。
//! 详细行为见 `linux/README.md` 与 `shared/protocol.md`。

mod selftest;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::Path;
use std::sync::{Arc, Mutex};
use vkey_hid::api::{ApiClient, Auth};
use vkey_hid::config;
use vkey_hid::crypto;
use vkey_hid::ctap2::authenticator::{Authenticator, ChangeNotifier};
use vkey_hid::policy::{self, EffectivePolicy};
use vkey_hid::store::{self, Identity, LocalStore, StoreBackend};
use vkey_hid::sync;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "vkey-hid",
    version,
    about = "vkey Linux 客户端：虚拟 FIDO2 密钥 + 零知识条目同步"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 首次接入：用 master_key 换取设备 token 并落盘身份
    Login {
        #[arg(long)]
        server: String,
        /// master_key 的 base32 形式（省略则交互输入）
        #[arg(long)]
        master_key: Option<String>,
        /// 覆盖服务端 username_hint
        #[arg(long)]
        username: Option<String>,
        /// 设备名（默认取主机名）
        #[arg(long = "device-name")]
        device_name: Option<String>,
    },
    /// 生成一次性配对码（第二台设备用 `pair --code` 领取）
    PairNew,
    /// 设置或移除主密码包裹（写到服务端 `users.wrapped_key`）
    Passwd {
        /// 移除主密码包裹（需两次确认；请先确认服务端策略允许无密码）
        #[arg(long)]
        clear: bool,
    },
    /// 第二台设备接入：用一次性配对码领取 master_key
    Pair {
        #[arg(long)]
        server: String,
        #[arg(long)]
        code: String,
        #[arg(long = "device-name")]
        device_name: Option<String>,
        /// 已有身份时允许覆盖
        #[arg(long)]
        force: bool,
    },
    /// uhid daemon（前台；systemd user service 使用）
    Run,
    /// 打印服务端、设备、条目数、策略与解锁状态
    Status,
    /// 手动同步一次
    Sync,
    /// 无 uhid 自检：makeCredential + getAssertion + DER 验签
    Selftest,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("vkey-hid: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Login {
            server,
            master_key,
            username,
            device_name,
        } => cmd_login(
            &server,
            master_key.as_deref(),
            username.as_deref(),
            device_name.as_deref(),
        ),
        Command::Pair {
            server,
            code,
            device_name,
            force,
        } => cmd_pair(&server, &code, device_name.as_deref(), force),
        Command::PairNew => cmd_pair_new(),
        Command::Passwd { clear } => cmd_passwd(clear),
        Command::Run => cmd_run(),
        Command::Status => cmd_status(),
        Command::Sync => cmd_sync(),
        Command::Selftest => {
            let ok = selftest::run()?;
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn cmd_login(
    server: &str,
    master_key_arg: Option<&str>,
    username_arg: Option<&str>,
    device_name_arg: Option<&str>,
) -> Result<()> {
    let dir = config::data_dir()?;
    let client = ApiClient::new(server)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())
        .context("登录前必须先读取服务端策略")?;

    let existing = store::load_identity(&dir).ok();
    let username = username_arg
        .map(str::to_string)
        .or_else(|| {
            if policy.username_hint.is_empty() {
                None
            } else {
                Some(policy.username_hint.clone())
            }
        })
        .or_else(|| existing.as_ref().map(|i| i.username.clone()))
        .unwrap_or_else(|| "default".to_string());

    let seed = match existing.as_ref() {
        Some(id) => crypto::b64_decode(&id.ed25519_seed).context("ed25519_seed 解码失败")?,
        None => crypto::random_bytes(crypto::ED25519_SEED_LEN)?,
    };
    if seed.len() != crypto::ED25519_SEED_LEN {
        bail!("ed25519 种子长度非法");
    }
    let pubkey = crypto::device_public_key(&seed)?;

    let master_key = Zeroizing::new(match master_key_arg {
        Some(s) => crypto::parse_master_key(s)?,
        None => {
            let input = config::read_master_key("master_key (base32): ")?;
            crypto::parse_master_key(&input)?
        }
    });
    let verifier = crypto::verifier(&master_key, &username)?;
    let device_name = device_name_arg
        .map(str::to_string)
        .or_else(|| existing.as_ref().map(|i| i.device_name.clone()))
        .unwrap_or_else(config::default_device_name);

    let resp = client
        .auth_token(
            &username,
            &crypto::b64_encode(&verifier),
            &device_name,
            platform(),
            &crypto::b64_encode(&pubkey),
        )
        .context("auth/token 失败（master_key 或用户名不正确？）")?;
    let token = crypto::b64_decode(&resp.token).context("token 解码失败")?;
    if token.len() != crypto::TOKEN_LEN {
        bail!("服务端返回的 token 长度非法");
    }

    let local_key = store::ensure_local_key(&dir)?;
    let local_wrapped = store::wrap_master_local(&master_key, &local_key)?;
    let (pw_salt_b64, wrapped_b64) = if policy.require_master_pw {
        let (salt, wrapped) = build_pw_wrap(
            &master_key,
            existing.as_ref(),
            &resp,
            &policy,
            "设置 vkey 主密码: ",
        )?;
        (
            Some(crypto::b64_encode(&salt)),
            crypto::b64_encode(&wrapped),
        )
    } else {
        (None, crypto::b64_encode(&local_wrapped))
    };

    // 服务端此前可能没有包裹（require_master_pw 刚打开）：本次设置后立即上传，
    // 否则 policy.require_master_pw_enforced 永远为 false，其它设备无法解包。
    if let Some(salt_b64) = pw_salt_b64.as_deref() {
        let auth = Auth::new(&seed, token.clone())?;
        client
            .set_password(&auth, salt_b64, &wrapped_b64)
            .context("登录成功，但上传主密码包裹失败")?;
    }

    let identity = Identity {
        server_url: client.base_url().to_string(),
        device_id: resp.device_id,
        device_name,
        username,
        ed25519_seed: crypto::b64_encode(&seed),
        token: resp.token,
        wrapped_master_key: wrapped_b64,
        pw_salt: pw_salt_b64,
        local_wrapped_master_key: Some(crypto::b64_encode(&local_wrapped)),
        created_at: config::now_unix(),
    };
    store::save_identity(&dir, &identity)?;
    if !dir.join("items.json").exists() {
        LocalStore::create(&dir, identity.clone(), master_key.clone())?;
    }

    println!("已登录");
    println!("  server:      {}", identity.server_url);
    println!(
        "  device:      {} ({})",
        identity.device_name, identity.device_id
    );
    println!("  username:    {}", identity.username);
    println!(
        "  policy:      require_master_pw={} ({})",
        policy.require_master_pw,
        policy.source.as_str()
    );
    println!("  data_dir:    {}", dir.display());
    Ok(())
}

fn cmd_pair(server: &str, code: &str, device_name_arg: Option<&str>, force: bool) -> Result<()> {
    let dir = config::data_dir()?;
    if dir.join("identity.json").exists() && !force {
        bail!(
            "{} 已存在身份；如需覆盖请加 --force（会覆盖本地条目缓存）",
            dir.display()
        );
    }
    let code_bytes = crypto::parse_pair_code(code)?;
    let client = ApiClient::new(server)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())
        .context("配对前必须先读取服务端策略")?;

    let seed = crypto::random_bytes(crypto::ED25519_SEED_LEN)?;
    let pubkey = crypto::device_public_key(&seed)?;
    let device_name = device_name_arg
        .map(str::to_string)
        .unwrap_or_else(config::default_device_name);

    let claim = client
        .pair_claim(code, &device_name, platform(), &crypto::b64_encode(&pubkey))
        .context("pair/claim 失败（配对码不存在/已用/过期？）")?;
    let kek = crypto::pair_kek(&code_bytes, &claim.code_id)?;
    let blob = crypto::b64_decode(&claim.blob).context("配对 blob 解码失败")?;
    let master_key = Zeroizing::new(
        crypto::open_self_contained(&kek, &blob, b"")
            .context("配对 blob 解密失败（配对码不匹配？）")?,
    );
    if master_key.len() != crypto::KEY_LEN {
        bail!("配对得到的 master_key 长度非法");
    }
    let token = crypto::b64_decode(&claim.token).context("token 解码失败")?;
    if token.len() != crypto::TOKEN_LEN {
        bail!("服务端返回的 token 长度非法");
    }

    let local_key = store::ensure_local_key(&dir)?;
    let local_wrapped = store::wrap_master_local(&master_key, &local_key)?;
    let auth = Auth::new(&seed, token.clone())?;
    let (pw_salt_b64, wrapped_b64) = match (claim.pw_salt.as_deref(), claim.wrapped_key.as_deref())
    {
        // 服务端已有包裹：用主密码验证并复用，避免为同一账号制造第二份包裹。
        (Some(salt_b64), Some(wrapped_b64)) if policy.require_master_pw => {
            let salt = crypto::b64_decode(salt_b64).context("pw_salt 解码失败")?;
            let blob = crypto::b64_decode(wrapped_b64).context("wrapped_key 解码失败")?;
            let password = config::read_password("vkey 主密码: ")?;
            let unlocked = store::unwrap_master_password(&password, &salt, &blob, &policy)
                .context("主密码不正确")?;
            if !crypto::equal_ct(&unlocked, &master_key) {
                bail!("主密码解开的是另一把 master_key");
            }
            (Some(salt_b64.to_string()), wrapped_b64.to_string())
        }
        // 服务端尚未存包裹：由本设备建立并上传。
        _ if policy.require_master_pw => {
            let salt = match claim.pw_salt.as_deref() {
                Some(s) => crypto::b64_decode(s).context("pw_salt 解码失败")?,
                None => store::new_pw_salt()?,
            };
            let password = config::read_new_password("设置 vkey 主密码: ")?;
            let wrapped = store::wrap_master_password(&master_key, &password, &salt, &policy)?;
            let salt_b64 = crypto::b64_encode(&salt);
            let wrapped_b64 = crypto::b64_encode(&wrapped);
            client
                .set_password(&auth, &salt_b64, &wrapped_b64)
                .context("上传主密码包裹失败")?;
            (Some(salt_b64), wrapped_b64)
        }
        _ => (None, crypto::b64_encode(&local_wrapped)),
    };

    let username = if policy.username_hint.is_empty() {
        "default".to_string()
    } else {
        policy.username_hint.clone()
    };
    let identity = Identity {
        server_url: client.base_url().to_string(),
        device_id: claim.device_id,
        device_name,
        username,
        ed25519_seed: crypto::b64_encode(&seed),
        token: claim.token,
        wrapped_master_key: wrapped_b64,
        pw_salt: pw_salt_b64,
        local_wrapped_master_key: Some(crypto::b64_encode(&local_wrapped)),
        created_at: config::now_unix(),
    };
    store::save_identity(&dir, &identity)?;
    // 配对设备以空缓存开始；`sync` 会拉取全部条目。
    LocalStore::create(&dir, identity.clone(), master_key.clone())?;

    println!("配对成功");
    println!("  server:      {}", identity.server_url);
    println!(
        "  device:      {} ({})",
        identity.device_name, identity.device_id
    );
    println!("  data_dir:    {}", dir.display());
    println!("下一步：执行 `vkey-hid sync` 拉取条目");
    Ok(())
}

fn cmd_pair_new() -> Result<()> {
    let dir = config::data_dir()?;
    let identity = store::load_identity(&dir)?;
    let client = ApiClient::new(&identity.server_url)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())?;
    let master_key = unlock_identity(&dir, &identity, &policy)?;
    let auth = auth_from_identity(&identity)?;

    let code = store::new_pair_code()?;
    let code_id = format!(
        "pair-{}-{}",
        config::now_unix(),
        crypto::hex_encode(&crypto::random_bytes(4)?)
    );
    let kek = crypto::pair_kek(&code, &code_id)?;
    let blob = crypto::seal_self_contained(&kek, &master_key, b"")?;
    let pw_salt = if policy.require_master_pw {
        identity.pw_salt.clone()
    } else {
        None
    };
    let resp = client.pair_new(
        &auth,
        &code_id,
        &crypto::b32_encode(&code),
        &crypto::b64_encode(&blob),
        pw_salt.as_deref(),
    )?;
    println!("配对码（10 分钟内有效，单次可用）：");
    println!("  {}", crypto::format_pair_code(&code));
    println!("  code_id:    {}", resp.code_id);
    println!("  expires_at: {}", resp.expires_at);
    println!();
    println!(
        "在另一台设备执行：vkey-hid pair --server {} --code <上面的配对码>",
        identity.server_url
    );
    Ok(())
}

/// 设置或移除主密码包裹（写服务端 `users.wrapped_key`）。
///
/// 设置：两次输入新密码 → Argon2id 包裹 master_key → POST /auth/password → 本地记 pw_salt。
/// 移除：两次 `yes` 确认 → DELETE /auth/password → 本地切回 local.key 包裹。
fn cmd_passwd(clear: bool) -> Result<()> {
    let dir = config::data_dir()?;
    let identity = store::load_identity(&dir)?;
    let client = ApiClient::new(&identity.server_url)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())?;
    let auth = auth_from_identity(&identity)?;
    // 设置/移除密码层都必须先拿到 master_key；只用 local.key，不能依赖密码层本身。
    let master_key = store::unlock_local_wrap(&dir, &identity)?;

    if clear {
        config::confirm_remove_password()?;
        client
            .clear_password(&auth)
            .context("DELETE /auth/password 失败")?;
        let local_wrapped = identity
            .local_wrapped_master_key
            .clone()
            .ok_or_else(|| anyhow!("本地身份缺少 local.key 包裹，拒绝删除服务端包裹"))?;
        let mut updated = identity.clone();
        updated.pw_salt = None;
        updated.wrapped_master_key = local_wrapped;
        store::save_identity(&dir, &updated)?;
        println!("已移除主密码包裹（服务端与本地）");
        if policy.require_master_pw {
            println!("警告：服务端策略仍要求主密码（require_master_pw=true），启动将被拒绝；");
            println!("      请由管理员执行 `vkeyd policy set --db <db> --require-master-pw=false`");
        }
        return Ok(());
    }

    let password = config::read_new_password("设置 vkey 主密码: ")?;
    let salt = store::new_pw_salt()?;
    let wrapped = store::wrap_master_password(&master_key, &password, &salt, &policy)?;
    let salt_b64 = crypto::b64_encode(&salt);
    let wrapped_b64 = crypto::b64_encode(&wrapped);
    client
        .set_password(&auth, &salt_b64, &wrapped_b64)
        .context("POST /auth/password 失败")?;

    let mut updated = identity.clone();
    updated.pw_salt = Some(salt_b64);
    updated.wrapped_master_key = wrapped_b64;
    store::save_identity(&dir, &updated)?;
    println!("主密码包裹已写入服务端");
    println!(
        "  kdf:         m={} t={} p={}",
        policy.kdf.m, policy.kdf.t, policy.kdf.p
    );
    println!("  data_dir:    {}", dir.display());
    Ok(())
}

fn cmd_run() -> Result<()> {
    let dir = config::data_dir()?;
    let identity = store::load_identity(&dir)?;
    let client = ApiClient::new(&identity.server_url)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())?;
    let master_key = unlock_identity(&dir, &identity, &policy)?;
    let master_key_retry = master_key.clone();
    let store = LocalStore::load(&dir, master_key)?;
    let auth = auth_from_identity(&identity)?;

    // 启动时先同步一次；失败不阻止 daemon（本地凭据仍可离线使用）。
    let store = match sync::sync_once(&client, &auth, store) {
        Ok((store, report)) => {
            eprintln!(
                "vkey-hid: 启动同步 pushed={} pulled={} conflicts={} seq={}",
                report.pushed, report.pulled, report.conflicts, report.seq
            );
            store
        }
        Err(err) => {
            eprintln!("vkey-hid: 启动同步失败（继续离线运行）: {err:#}");
            LocalStore::load(&dir, master_key_retry)?
        }
    };

    let shared = Arc::new(Mutex::new(store));
    let trigger: Arc<dyn ChangeNotifier> = Arc::new(sync::SyncTrigger::spawn(
        shared.clone(),
        client.clone(),
        auth,
    ));
    let backend = StoreBackend::new(shared, trigger);
    let authenticator = Authenticator::new(backend);

    #[cfg(target_os = "linux")]
    {
        vkey_hid::ctap2::uhid::run_daemon(authenticator)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = authenticator;
        Err(anyhow!(
            "`run` 需要 Linux /dev/uhid；Windows 上请使用 selftest/status/sync"
        ))
    }
}

fn cmd_status() -> Result<()> {
    let dir = config::data_dir()?;
    let identity = store::load_identity(&dir)?;
    let client = ApiClient::new(&identity.server_url)?;
    let policy_res = policy::fetch_and_resolve(&dir, || client.policy());
    let item_count = store::disk_item_count(&dir).unwrap_or(0);
    let seq = read_seq(&dir).unwrap_or(0);

    println!("server_url:  {}", identity.server_url);
    println!(
        "device:      {} ({})",
        identity.device_name, identity.device_id
    );
    println!("username:    {}", identity.username);
    println!("items:       {item_count}");
    println!("seq:         {seq}");
    println!("data_dir:    {}", dir.display());

    match policy_res {
        Ok(policy) => {
            println!(
                "policy:      require_master_pw={} enforced={} (source={}{})",
                policy.require_master_pw,
                policy.require_master_pw_enforced,
                policy.source.as_str(),
                if policy.source == policy::PolicySource::Cache {
                    "，服务端不可达"
                } else {
                    ""
                }
            );
            if policy.require_master_pw_enforced {
                if identity.has_pw_wrap() {
                    println!("unlocked:    locked（需要主密码；run/sync 时提示输入）");
                } else {
                    println!("unlocked:    locked（本地缺少主密码包裹，请重新 login 或 pair）");
                }
            } else if policy.require_master_pw {
                println!("unlocked:    locked（服务端未存密码包裹，请先执行 `vkey-hid passwd`）");
            } else {
                match store::unlock_master(&dir, &identity, &policy, None) {
                    Ok(_) => println!("unlocked:    true"),
                    Err(err) => println!("unlocked:    false（{err}）"),
                }
            }
        }
        Err(err) => {
            println!("policy:      unknown（服务端不可达且无缓存）");
            println!("unlocked:    unknown（{err}）");
        }
    }
    Ok(())
}

fn cmd_sync() -> Result<()> {
    let dir = config::data_dir()?;
    let identity = store::load_identity(&dir)?;
    let client = ApiClient::new(&identity.server_url)?;
    let policy = policy::fetch_and_resolve(&dir, || client.policy())?;
    let master_key = unlock_identity(&dir, &identity, &policy)?;
    let store = LocalStore::load(&dir, master_key)?;
    let auth = auth_from_identity(&identity)?;
    let (_store, report) = sync::sync_once(&client, &auth, store)?;
    println!(
        "同步完成：pushed={} pulled={} conflicts={} seq={}{}",
        report.pushed,
        report.pulled,
        report.conflicts,
        report.seq,
        if report.full_reload {
            "（服务端回滚，已全量重拉）"
        } else {
            ""
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 共用 helper
// ---------------------------------------------------------------------------

fn platform() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unknown"
    }
}

fn auth_from_identity(identity: &Identity) -> Result<Auth> {
    Auth::from_encoded(&identity.ed25519_seed, &identity.token)
}

/// 按策略解锁 master_key；policy 要求密码或 local.key 不可用时提示输入。
/// 按服务端策略解锁 master_key。
///
/// - `enforced=true`：提示输入主密码，用密码包裹解包（失败即硬失败，不回退 local.key）；
/// - `require=true` 但 `enforced=false`：`ensure_unlockable` 直接报错，要求先 `passwd`；
/// - 否则：用 `local.key` 解包。
fn unlock_identity(
    dir: &Path,
    identity: &Identity,
    policy: &EffectivePolicy,
) -> Result<Zeroizing<Vec<u8>>> {
    policy::ensure_unlockable(policy, identity.has_pw_wrap())?;
    if policy.require_master_pw_enforced {
        let password = config::read_password("vkey 主密码: ")?;
        return store::unlock_by_policy(dir, identity, policy, Some(password.as_str()));
    }
    store::unlock_by_policy(dir, identity, policy, None)
}

/// 构造主密码包裹；优先复用既有包裹/服务端包裹并校验密码。
fn build_pw_wrap(
    master_key: &[u8],
    existing: Option<&Identity>,
    resp: &vkey_hid::api::AuthTokenResponse,
    policy: &EffectivePolicy,
    new_prompt: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(identity) = existing {
        if identity.has_pw_wrap() {
            let salt = identity.pw_salt_bytes()?;
            let blob = identity.wrapped_bytes()?;
            let password = config::read_password("vkey 主密码: ")?;
            let unlocked = store::unwrap_master_password(&password, &salt, &blob, policy)
                .context("主密码不正确")?;
            if !crypto::equal_ct(&unlocked, master_key) {
                bail!("主密码解开的是另一把 master_key；请使用当前 master_key 对应的主密码");
            }
            return Ok((salt, blob));
        }
    }
    if let (Some(salt_b64), Some(wrapped_b64)) = (&resp.pw_salt, &resp.wrapped_key) {
        let salt = crypto::b64_decode(salt_b64).context("服务端 pw_salt 解码失败")?;
        let blob = crypto::b64_decode(wrapped_b64).context("服务端 wrapped_key 解码失败")?;
        let password = config::read_password("vkey 主密码: ")?;
        let unlocked = store::unwrap_master_password(&password, &salt, &blob, policy)
            .context("主密码不正确")?;
        if !crypto::equal_ct(&unlocked, master_key) {
            bail!("服务端 wrapped_key 与提供的 master_key 不一致");
        }
        return Ok((salt, blob));
    }
    let password = config::read_new_password(new_prompt)?;
    let salt = store::new_pw_salt()?;
    let blob = store::wrap_master_password(master_key, &password, &salt, policy)?;
    Ok((salt, blob))
}

fn read_seq(dir: &Path) -> Result<i64> {
    let path = dir.join("seq");
    match config::read_optional(&path)? {
        None => Ok(0),
        Some(data) => {
            let text = String::from_utf8_lossy(&data);
            text.trim()
                .parse::<i64>()
                .with_context(|| format!("seq 文件内容非法: {}", text.trim()))
        }
    }
}
