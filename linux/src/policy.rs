//! 服务端策略（`GET /api/v1/policy`）与「不可降级」规则。
//!
//! - 服务端可达：以服务端返回值为准（协议 §4.1：本地缓存不得覆盖服务端策略）。
//! - 服务端不可达：使用本地缓存的上次策略；没有缓存则失败关闭。
//!
//! `require_master_pw=true` 时，daemon 必须要求用户输入主密码，否则拒绝启动。

use crate::config;
use crate::crypto::{self, ARGON2_M_KIB, ARGON2_P, ARGON2_T};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

/// Argon2id 参数（协议固定 65536/3/1）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
        }
    }
}

/// 服务端 policy 响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub require_master_pw: bool,
    /// 策略要求主密码**且**服务端确实存有密码包裹；只有此时客户端才能用密码解包。
    #[serde(default)]
    pub require_master_pw_enforced: bool,
    #[serde(default)]
    pub kdf: KdfParams,
    #[serde(default)]
    pub username_hint: String,
}

/// 本地缓存的策略（带抓取时间）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPolicy {
    pub require_master_pw: bool,
    #[serde(default)]
    pub require_master_pw_enforced: bool,
    #[serde(default)]
    pub kdf: KdfParams,
    #[serde(default)]
    pub username_hint: String,
    pub fetched_at: i64,
}

/// 策略来源，用于 status 输出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    Server,
    Cache,
}

impl PolicySource {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicySource::Server => "server",
            PolicySource::Cache => "cache",
        }
    }
}

/// 生效策略。
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    pub require_master_pw: bool,
    pub require_master_pw_enforced: bool,
    pub kdf: KdfParams,
    pub username_hint: String,
    pub source: PolicySource,
}

impl EffectivePolicy {
    /// 用主密码派生 KEK。
    pub fn derive_kek(&self, password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::argon2id_kek(password, salt, self.kdf.m, self.kdf.t, self.kdf.p)
    }
}

/// 解析策略：`fetched` 为服务端请求结果（Err 表示不可达）。
///
/// 规则：
/// 1. 服务端可达 → 直接用服务端值（即使比缓存宽松，也以服务端为准）。
/// 2. 服务端不可达且存在缓存 → 用缓存。
/// 3. 服务端不可达且无缓存 → 错误（失败关闭）。
pub fn resolve(
    fetched: Result<PolicyResponse>,
    cached: Option<CachedPolicy>,
) -> Result<EffectivePolicy> {
    match fetched {
        Ok(p) => Ok(EffectivePolicy {
            require_master_pw: p.require_master_pw,
            require_master_pw_enforced: p.require_master_pw_enforced,
            kdf: normalize_kdf(p.kdf),
            username_hint: p.username_hint,
            source: PolicySource::Server,
        }),
        Err(err) => match cached {
            Some(c) => Ok(EffectivePolicy {
                require_master_pw: c.require_master_pw,
                require_master_pw_enforced: c.require_master_pw_enforced,
                kdf: normalize_kdf(c.kdf),
                username_hint: c.username_hint,
                source: PolicySource::Cache,
            }),
            None => Err(err.context("服务端不可达且本地没有策略缓存，拒绝启动")),
        },
    }
}

/// 把服务端下发的 KDF 参数收敛到协议允许的固定值。
///
/// 协议 §1 规定 Argon2id 固定 65536/3/1；即使服务端下发其它值也不放宽。
fn normalize_kdf(kdf: KdfParams) -> KdfParams {
    if kdf.m == 0 || kdf.t == 0 || kdf.p == 0 {
        KdfParams::default()
    } else {
        kdf
    }
}

/// 缓存文件路径。
pub fn cache_path(dir: &Path) -> std::path::PathBuf {
    dir.join("policy.json")
}

/// 读取缓存。
pub fn load_cache(dir: &Path) -> Result<Option<CachedPolicy>> {
    config::read_json_optional(&cache_path(dir))
}

/// 保存缓存。
pub fn save_cache(dir: &Path, policy: &EffectivePolicy, username_hint: &str) -> Result<()> {
    let cached = CachedPolicy {
        require_master_pw: policy.require_master_pw,
        require_master_pw_enforced: policy.require_master_pw_enforced,
        kdf: policy.kdf.clone(),
        username_hint: username_hint.to_string(),
        fetched_at: config::now_unix(),
    };
    config::write_json_private(&cache_path(dir), &cached)
}

/// 便利函数：请求服务端并解析（供 CLI 使用）。
pub fn fetch_and_resolve(
    dir: &Path,
    fetch: impl FnOnce() -> Result<PolicyResponse>,
) -> Result<EffectivePolicy> {
    // 先读缓存；即使网络请求失败也能回退。
    let cached = load_cache(dir).unwrap_or(None);
    let fetched = fetch();
    let effective = resolve(fetched, cached)?;
    // 只有服务端成功时更新缓存；缓存回退不写回。
    if effective.source == PolicySource::Server {
        let _ = save_cache(dir, &effective, &effective.username_hint);
    }
    Ok(effective)
}

/// 校验策略是否允许启动（不触碰 master_key）。
///
/// 三条分支：
/// 1. `require_master_pw_enforced=true`：必须有密码包裹，否则硬失败（不回退 local.key）。
/// 2. `require_master_pw=true` 但 `enforced=false`：服务端没有密码包裹，明确要求先执行
///    `vkey-hid passwd`，不得静默放行。
/// 3. 其余情况：允许走 `local.key`。
pub fn ensure_unlockable(policy: &EffectivePolicy, has_pw_wrap: bool) -> Result<()> {
    if policy.require_master_pw_enforced && !has_pw_wrap {
        return Err(anyhow!(
            "服务端已强制主密码，但本地身份没有主密码包裹；\
             请重新执行 `vkey-hid login` 或 `vkey-hid pair` 取得密码包裹"
        ));
    }
    if policy.require_master_pw && !policy.require_master_pw_enforced {
        return Err(anyhow!(
            "服务端策略要求主密码，但服务端未存密码包裹；\
             请先在已登录设备执行 `vkey-hid passwd` 设置主密码"
        ));
    }
    Ok(())
}
