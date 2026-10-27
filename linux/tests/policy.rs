//! 策略解析与「不可降级 / 主密码三条分支」规则。

use anyhow::anyhow;
use vkey_hid::policy::{self, CachedPolicy, KdfParams, PolicyResponse, PolicySource};

fn server_state(require: bool, enforced: bool) -> PolicyResponse {
    PolicyResponse {
        require_master_pw: require,
        require_master_pw_enforced: enforced,
        kdf: KdfParams::default(),
        username_hint: "default".into(),
    }
}

fn server(require: bool) -> PolicyResponse {
    server_state(require, false)
}

fn cached(require: bool) -> CachedPolicy {
    CachedPolicy {
        require_master_pw: require,
        require_master_pw_enforced: false,
        kdf: KdfParams::default(),
        username_hint: "default".into(),
        fetched_at: 1,
    }
}

#[test]
fn server_reachable_is_authoritative() {
    // 服务端说 false，即使缓存是 true 也以服务端为准（协议 §4.1）。
    let p = policy::resolve(Ok(server(false)), Some(cached(true))).unwrap();
    assert!(!p.require_master_pw);
    assert_eq!(p.source, PolicySource::Server);

    let p = policy::resolve(Ok(server(true)), Some(cached(false))).unwrap();
    assert!(p.require_master_pw);
    assert_eq!(p.source, PolicySource::Server);
}

#[test]
fn unreachable_falls_back_to_cache_without_relaxing() {
    let p = policy::resolve(Err(anyhow!("offline")), Some(cached(true))).unwrap();
    assert!(p.require_master_pw, "上次 true 必须保持 true");
    assert_eq!(p.source, PolicySource::Cache);

    let p = policy::resolve(Err(anyhow!("offline")), Some(cached(false))).unwrap();
    assert!(!p.require_master_pw);
    assert_eq!(p.source, PolicySource::Cache);
}

#[test]
fn unreachable_without_cache_fails_closed() {
    let err = policy::resolve(Err(anyhow!("offline")), None).unwrap_err();
    assert!(format!("{err:#}").contains("没有策略缓存"));
}

#[test]
fn enforced_true_requires_password_wrap() {
    let p = policy::resolve(Ok(server_state(true, true)), None).unwrap();
    assert!(p.require_master_pw_enforced);
    // 本地没有密码包裹时必须硬失败（不能回退 local.key）。
    let err = policy::ensure_unlockable(&p, false).unwrap_err();
    assert!(format!("{err:#}").contains("没有主密码包裹"));
    // 有包裹则允许进入密码解锁流程。
    assert!(policy::ensure_unlockable(&p, true).is_ok());
}

#[test]
fn require_without_enforced_points_to_passwd() {
    let p = policy::resolve(Ok(server_state(true, false)), None).unwrap();
    assert!(p.require_master_pw);
    assert!(!p.require_master_pw_enforced);
    // 服务端缺包裹：无论本地有没有包裹都必须明确报错提示 `vkey-hid passwd`。
    for has_wrap in [false, true] {
        let err = policy::ensure_unlockable(&p, has_wrap).unwrap_err();
        assert!(format!("{err:#}").contains("vkey-hid passwd"));
    }
}

#[test]
fn policy_false_allows_local_key() {
    let p = policy::resolve(Ok(server_state(false, false)), None).unwrap();
    assert!(policy::ensure_unlockable(&p, false).is_ok());
}

#[test]
fn kdf_defaults_are_protocol_values() {
    let kdf = KdfParams::default();
    assert_eq!((kdf.m, kdf.t, kdf.p), (65536, 3, 1));
}
