//! 本地身份与条目缓存。
//!
//! 落盘文件（Unix 0600）：
//! - `local.key`：32B 随机 KEK（无主密码场景包裹 master_key）
//! - `identity.json`：设备身份（Ed25519 种子、token、package 后的 master_key）
//! - `items.json`：条目缓存，**只存密文**（`ct` / `nonce`），私钥不落明文
//! - `seq`：上次同步到的服务端 version
//!
//! `items.json` 中的明文只存在于进程内存；写入时用 master_key 派生的 item_key
//! 重新加密，签名后立即从内存丢弃私钥。

use crate::config;
use crate::crypto::{self, NONCE_LEN, PAIR_CODE_LEN, PW_SALT_LEN};
use crate::ctap2::authenticator::{
    ChangeNotifier, CredentialBackend, CredentialData, NewCredential,
};
use crate::policy::EffectivePolicy;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// identity.json 结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub server_url: String,
    pub device_id: String,
    pub device_name: String,
    pub username: String,
    /// base64url(32B Ed25519 种子)。
    pub ed25519_seed: String,
    /// base64url(32B token)。
    pub token: String,
    /// 当前生效的 master_key 包裹（`pw_salt` 存在时为密码包裹，否则为 local.key 包裹）。
    pub wrapped_master_key: String,
    #[serde(default)]
    pub pw_salt: Option<String>,
    /// 始终保留的 local.key 包裹（策略从 true 放宽到 false 时可回退）。
    #[serde(default)]
    pub local_wrapped_master_key: Option<String>,
    pub created_at: i64,
}

impl Identity {
    /// 是否已有主密码包裹。
    pub fn has_pw_wrap(&self) -> bool {
        self.pw_salt.is_some()
    }

    /// 解码 pw_salt。
    pub fn pw_salt_bytes(&self) -> Result<Vec<u8>> {
        let s = self
            .pw_salt
            .as_deref()
            .ok_or_else(|| anyhow!("identity 中没有 pw_salt"))?;
        let bytes = crypto::b64_decode(s).context("pw_salt 解码失败")?;
        if bytes.len() != PW_SALT_LEN {
            bail!("pw_salt 必须 {PW_SALT_LEN} 字节");
        }
        Ok(bytes)
    }

    /// 解码当前包裹。
    pub fn wrapped_bytes(&self) -> Result<Vec<u8>> {
        crypto::b64_decode(&self.wrapped_master_key).context("wrapped_master_key 解码失败")
    }

    /// 解码 local.key 包裹。
    pub fn local_wrapped_bytes(&self) -> Result<Vec<u8>> {
        match self.local_wrapped_master_key.as_deref() {
            Some(s) => crypto::b64_decode(s).context("local_wrapped_master_key 解码失败"),
            None => self.wrapped_bytes(),
        }
    }
}

/// 一条本地缓存条目（落盘只含密文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalItem {
    pub id: String,
    pub kind: String,
    pub rp_id: String,
    #[serde(default)]
    pub ct: String,
    #[serde(default)]
    pub nonce: String,
    pub version: i64,
    #[serde(default)]
    pub base_version: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub deleted_at: i64,
    #[serde(default)]
    pub dirty: bool,
    /// 内存中的明文；不落盘（落盘只保留 ct/nonce）。
    #[serde(skip)]
    pub plaintext: Option<Value>,
}

impl LocalItem {
    /// 是否为墓碑。
    pub fn is_deleted(&self) -> bool {
        self.deleted_at != 0
    }

    /// 构造推送条目。
    pub fn to_push_item(&self) -> Result<crate::api::PushItem> {
        if !self.is_deleted() && (self.ct.is_empty() || self.nonce.is_empty()) {
            bail!("本地条目 {} 缺少密文", self.id);
        }
        Ok(crate::api::PushItem {
            id: self.id.clone(),
            kind: self.kind.clone(),
            rp_id: self.rp_id.clone(),
            ct: self.ct.clone(),
            nonce: self.nonce.clone(),
            base_version: self.base_version,
            updated_at: self.updated_at,
            deleted_at: self.deleted_at,
        })
    }
}

/// items.json 顶层结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ItemsFile {
    v: u32,
    items: Vec<LocalItem>,
}

/// 本地存储。
pub struct LocalStore {
    dir: PathBuf,
    identity: Identity,
    master_key: Zeroizing<Vec<u8>>,
    items: BTreeMap<String, LocalItem>,
    seq: i64,
}

impl LocalStore {
    /// 加载本地存储；master_key 必须能解开 items.json 中的条目。
    pub fn load(dir: &Path, master_key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let identity = load_identity(dir)?;
        let items = load_items(dir, &master_key)?;
        let seq = load_seq(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            identity,
            master_key,
            items,
            seq,
        })
    }

    /// 用新身份创建空存储。
    pub fn create(dir: &Path, identity: Identity, master_key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut store = Self {
            dir: dir.to_path_buf(),
            identity,
            master_key,
            items: BTreeMap::new(),
            seq: 0,
        };
        store.save()?;
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    pub fn seq(&self) -> i64 {
        self.seq
    }

    pub fn set_seq(&mut self, seq: i64) {
        self.seq = seq;
    }

    pub fn item_count(&self) -> usize {
        self.items.values().filter(|i| !i.is_deleted()).count()
    }

    pub fn items(&self) -> impl Iterator<Item = &LocalItem> {
        self.items.values()
    }

    pub fn get(&self, id: &str) -> Option<&LocalItem> {
        self.items.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut LocalItem> {
        self.items.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<LocalItem> {
        self.items.remove(id)
    }

    /// 直接插入/更新明文条目（调用方负责 item_key 加密前的一致性字段）。
    // 参数是条目的一整套字段，拆结构体会让唯一调用处更啰嗦，故保留平铺参数。
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_plaintext(
        &mut self,
        id: String,
        kind: String,
        rp_id: String,
        plaintext: Value,
        base_version: i64,
        version: i64,
        updated_at: i64,
    ) -> Result<()> {
        if id.is_empty() || id.len() > 128 {
            bail!("item id 必须为 1..128 字节");
        }
        if kind != "totp" && kind != "webauthn" {
            bail!("kind 必须是 totp 或 webauthn");
        }
        if rp_id.is_empty() || rp_id.len() > 255 {
            bail!("rp_id 必须为 1..255 字节");
        }
        if let Some(existing) = self.items.get(&id) {
            if existing.kind != kind || existing.rp_id != rp_id {
                bail!("条目 {id} 的 kind/rp_id 创建后不可变");
            }
        }
        self.items.insert(
            id.clone(),
            LocalItem {
                id,
                kind,
                rp_id,
                ct: String::new(),
                nonce: String::new(),
                version,
                base_version,
                updated_at,
                deleted_at: 0,
                dirty: true,
                plaintext: Some(plaintext),
            },
        );
        Ok(())
    }

    /// 修改明文并标记 dirty（保留未知字段）。
    pub fn mutate_plaintext<F>(&mut self, id: &str, f: F) -> Result<()>
    where
        F: FnOnce(&mut Value) -> Result<()>,
    {
        let item = self
            .items
            .get_mut(id)
            .ok_or_else(|| anyhow!("条目不存在: {id}"))?;
        let value = item
            .plaintext
            .as_mut()
            .ok_or_else(|| anyhow!("条目 {id} 没有解密后的明文"))?;
        f(value)?;
        item.updated_at = config::now_unix();
        item.dirty = true;
        Ok(())
    }

    /// 所有待推送条目。
    pub fn dirty_items(&self) -> Result<Vec<crate::api::PushItem>> {
        self.items
            .values()
            .filter(|i| i.dirty)
            .map(|i| i.to_push_item())
            .collect()
    }

    /// 应用一次拉取结果。返回 `true` 表示需要全量重拉（服务端回滚）。
    pub fn apply_pull(&mut self, page: &crate::api::ItemsPage) -> Result<bool> {
        if page.next < self.seq {
            return Ok(true);
        }
        for wire in &page.items {
            self.apply_wire_item(wire)?;
        }
        self.seq = page.next;
        self.save()?;
        Ok(false)
    }

    /// 应用单条线上条目（不修改 seq）。
    pub fn apply_wire_item(&mut self, wire: &crate::api::ItemWire) -> Result<()> {
        if wire.deleted_at != 0 {
            if let Some(existing) = self.items.get(&wire.id).cloned() {
                if existing.dirty {
                    self.write_conflict_file(&existing)?;
                }
            }
            self.items.remove(&wire.id);
            return Ok(());
        }
        let ct = crypto::b64_decode(&wire.ct).context("ct 解码失败")?;
        let nonce = crypto::b64_decode(&wire.nonce).context("nonce 解码失败")?;
        if nonce.len() != NONCE_LEN {
            bail!("条目 {} 的 nonce 必须 {NONCE_LEN} 字节", wire.id);
        }
        let plaintext = crypto::open_item(&self.master_key, &wire.id, &ct, &nonce)
            .with_context(|| format!("条目 {} 解密失败", wire.id))?;
        let value: Value = serde_json::from_slice(&plaintext)
            .with_context(|| format!("条目 {} 明文不是合法 JSON", wire.id))?;
        self.items.insert(
            wire.id.clone(),
            LocalItem {
                id: wire.id.clone(),
                kind: wire.kind.clone(),
                rp_id: wire.rp_id.clone(),
                ct: wire.ct.clone(),
                nonce: wire.nonce.clone(),
                version: wire.version,
                base_version: wire.version,
                updated_at: wire.updated_at,
                deleted_at: 0,
                dirty: false,
                plaintext: Some(value),
            },
        );
        Ok(())
    }

    /// 服务端回滚时清空本地缓存（dirty 条目先落冲突副本）。
    pub fn reset_for_full_reload(&mut self) -> Result<()> {
        let dirty: Vec<LocalItem> = self.items.values().filter(|i| i.dirty).cloned().collect();
        for item in &dirty {
            self.write_conflict_file(item)?;
        }
        self.items.clear();
        self.seq = 0;
        self.save()?;
        Ok(())
    }

    /// 应用推送结果；返回需要重新拉取的条目 id（conflict / rejected）。
    pub fn apply_push_results(
        &mut self,
        results: &[crate::api::PushResult],
    ) -> Result<Vec<String>> {
        let mut reload = Vec::new();
        for res in results {
            let Some(existing) = self.items.get(&res.id).cloned() else {
                continue;
            };
            match res.status.as_str() {
                "applied" => {
                    if let Some(item) = self.items.get_mut(&res.id) {
                        item.version = res.version;
                        item.base_version = res.version;
                        item.dirty = false;
                    }
                }
                "conflict" | "rejected" => {
                    self.write_conflict_file(&existing)?;
                    self.items.remove(&res.id);
                    reload.push(res.id.clone());
                }
                other => {
                    bail!("服务端返回未知写入状态: {other}");
                }
            }
        }
        self.save()?;
        Ok(reload)
    }

    /// 把本地副本写成 `conflicts/<id>.conflict-<ts>.json`（只含密文，可恢复）。
    pub fn write_conflict_file(&self, item: &LocalItem) -> Result<PathBuf> {
        let dir = self.dir.join("conflicts");
        config::ensure_dir(&dir)?;
        let safe = sanitize_id(&item.id);
        let path = dir.join(format!("{}.conflict-{}.json", safe, config::now_unix()));
        let body = json!({
            "item_id": item.id,
            "kind": item.kind,
            "rp_id": item.rp_id,
            "ct": item.ct,
            "nonce": item.nonce,
            "version": item.version,
            "base_version": item.base_version,
            "updated_at": item.updated_at,
            "deleted_at": item.deleted_at,
            "note": "LWW 冲突落败副本：密文形式保留，可用 master_key 解密恢复",
        });
        config::write_json_private(&path, &body)?;
        Ok(path)
    }

    /// 落盘：dirty 条目重新加密为密文，明文不写入磁盘。
    pub fn save(&mut self) -> Result<()> {
        for item in self.items.values_mut() {
            if item.is_deleted() {
                item.ct.clear();
                item.nonce.clear();
                continue;
            }
            if item.dirty || item.ct.is_empty() || item.nonce.is_empty() {
                let value = item
                    .plaintext
                    .as_ref()
                    .ok_or_else(|| anyhow!("条目 {} 缺少明文，无法加密落盘", item.id))?;
                let plaintext = serde_json::to_vec(value)?;
                let (ct, nonce) = crypto::seal_item_random(&self.master_key, &item.id, &plaintext)?;
                item.ct = crypto::b64_encode(&ct);
                item.nonce = crypto::b64_encode(&nonce);
            }
        }
        let file = ItemsFile {
            v: 1,
            items: self.items.values().cloned().collect(),
        };
        config::write_json_private(&self.dir.join("items.json"), &file)?;
        save_seq(&self.dir, self.seq)?;
        Ok(())
    }
}

/// 读取 identity.json。
pub fn load_identity(dir: &Path) -> Result<Identity> {
    let path = dir.join("identity.json");
    config::read_json(&path).with_context(|| "读取 identity.json 失败，请先 login 或 pair")
}

/// 写入 identity.json。
pub fn save_identity(dir: &Path, identity: &Identity) -> Result<()> {
    config::write_json_private(&dir.join("identity.json"), identity)
}

/// 读取或生成 local.key（32B）。
pub fn ensure_local_key(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("local.key");
    if let Some(data) = config::read_optional(&path)? {
        if data.len() != crypto::KEY_LEN {
            bail!("local.key 必须 {} 字节", crypto::KEY_LEN);
        }
        return Ok(data);
    }
    let key = crypto::random_bytes(crypto::KEY_LEN)?;
    config::write_private(&path, &key)?;
    Ok(key)
}

/// 读取 local.key。
pub fn read_local_key(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("local.key");
    let data =
        config::read_optional(&path)?.ok_or_else(|| anyhow!("缺少 local.key，请先 login"))?;
    if data.len() != crypto::KEY_LEN {
        bail!("local.key 必须 {} 字节", crypto::KEY_LEN);
    }
    Ok(data)
}

/// 用 local.key 包裹 master_key（自包含 nonce||ct||tag）。
pub fn wrap_master_local(master_key: &[u8], local_key: &[u8]) -> Result<Vec<u8>> {
    let kek = crypto::local_wrap_kek(local_key)?;
    crypto::seal_self_contained(&kek, master_key, b"")
}

/// 用 local.key 解包 master_key。
pub fn unwrap_master_local(local_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let kek = crypto::local_wrap_kek(local_key)?;
    let plain = crypto::open_self_contained(&kek, blob, b"")?;
    if plain.len() != crypto::KEY_LEN {
        bail!("解包后的 master_key 长度非法");
    }
    Ok(Zeroizing::new(plain))
}

/// 用主密码派生 KEK 包裹 master_key。
pub fn wrap_master_password(
    master_key: &[u8],
    password: &str,
    salt: &[u8],
    policy: &EffectivePolicy,
) -> Result<Vec<u8>> {
    let kek = policy.derive_kek(password, salt)?;
    crypto::seal_self_contained(&kek, master_key, b"")
}

/// 用主密码解包 master_key。
pub fn unwrap_master_password(
    password: &str,
    salt: &[u8],
    blob: &[u8],
    policy: &EffectivePolicy,
) -> Result<Zeroizing<Vec<u8>>> {
    let kek = policy.derive_kek(password, salt)?;
    let plain = crypto::open_self_contained(&kek, blob, b"").context("主密码错误或包裹数据损坏")?;
    if plain.len() != crypto::KEY_LEN {
        bail!("解包后的 master_key 长度非法");
    }
    Ok(Zeroizing::new(plain))
}

/// 按策略解锁 master_key。
///
/// `policy.require_master_pw=true` 时必须提供 `password`；否则用 local.key。
pub fn unlock_master(
    dir: &Path,
    identity: &Identity,
    policy: &EffectivePolicy,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    if policy.require_master_pw {
        let password = password.ok_or_else(|| anyhow!("服务端要求主密码，但没有提供"))?;
        let salt = identity.pw_salt_bytes()?;
        let blob = identity.wrapped_bytes()?;
        return unwrap_master_password(password, &salt, &blob, policy);
    }
    // 未强制主密码：优先使用 local.key 包裹；没有时回退到密码包裹（需要 password）。
    if identity.local_wrapped_master_key.is_some() || !identity.has_pw_wrap() {
        let local_key = read_local_key(dir)?;
        let blob = identity.local_wrapped_bytes()?;
        return unwrap_master_local(&local_key, &blob);
    }
    let password = password.ok_or_else(|| anyhow!("本地身份只有密码包裹，请提供主密码"))?;
    let salt = identity.pw_salt_bytes()?;
    let blob = identity.wrapped_bytes()?;
    unwrap_master_password(password, &salt, &blob, policy)
}

/// 用本机 `local.key` 解包 master_key（**不经过**主密码策略）。
///
/// `vkey-hid passwd` 用它取得 master_key：设置/移除密码层时不能依赖密码层本身。
pub fn unlock_local_wrap(dir: &Path, identity: &Identity) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = identity
        .local_wrapped_master_key
        .as_deref()
        .ok_or_else(|| anyhow!("本地身份缺少 local.key 包裹，无法在不输入主密码的情况下解锁"))?;
    let blob = crypto::b64_decode(encoded).context("local_wrapped_master_key 解码失败")?;
    let local_key = read_local_key(dir)?;
    unwrap_master_local(&local_key, &blob)
}

/// 按服务端策略解锁 master_key（启动路径统一入口）。
///
/// 规则（与 [`crate::policy::ensure_unlockable`] 一致）：
/// - `require_master_pw_enforced=true`：必须提供密码并用密码包裹解包，**不回退** local.key；
/// - `require_master_pw=true` 但未 enforced：直接报错（服务端缺包裹）；
/// - 否则：用 local.key 解包。
pub fn unlock_by_policy(
    dir: &Path,
    identity: &Identity,
    policy: &EffectivePolicy,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    crate::policy::ensure_unlockable(policy, identity.has_pw_wrap())?;
    if policy.require_master_pw_enforced {
        let password = password.ok_or_else(|| anyhow!("服务端要求主密码，但没有提供"))?;
        let salt = identity.pw_salt_bytes()?;
        let blob = identity.wrapped_bytes()?;
        return unwrap_master_password(password, &salt, &blob, policy);
    }
    unlock_local_wrap(dir, identity)
}

/// 读取条目缓存（用于 status 不持有 master_key 时统计数量）。
pub fn count_items_on_disk(dir: &Path) -> Result<usize> {
    let path = dir.join("items.json");
    match config::read_optional(&path)? {
        None => Ok(0),
        Some(data) => {
            let file: ItemsFile = serde_json::from_slice(&data)
                .with_context(|| format!("解析 {} 失败", path.display()))?;
            Ok(file.items.iter().filter(|i| i.deleted_at == 0).count())
        }
    }
}

/// 生成条目的 item id（16B 随机 → base64url 22 字符）。
pub fn new_item_id() -> Result<String> {
    Ok(crypto::b64_encode(&crypto::random_bytes(16)?))
}

/// 生成配对码原始 32B。
pub fn new_pair_code() -> Result<Vec<u8>> {
    crypto::random_bytes(PAIR_CODE_LEN)
}

/// 生成 pw_salt 16B。
pub fn new_pw_salt() -> Result<Vec<u8>> {
    crypto::random_bytes(PW_SALT_LEN)
}

fn load_items(dir: &Path, master_key: &[u8]) -> Result<BTreeMap<String, LocalItem>> {
    let path = dir.join("items.json");
    let Some(data) = config::read_optional(&path)? else {
        return Ok(BTreeMap::new());
    };
    let file: ItemsFile =
        serde_json::from_slice(&data).with_context(|| format!("解析 {} 失败", path.display()))?;
    let mut out = BTreeMap::new();
    for mut item in file.items {
        if item.deleted_at != 0 {
            continue;
        }
        let ct = crypto::b64_decode(&item.ct)
            .with_context(|| format!("条目 {} 的 ct 解码失败", item.id))?;
        let nonce = crypto::b64_decode(&item.nonce)
            .with_context(|| format!("条目 {} 的 nonce 解码失败", item.id))?;
        let plaintext = crypto::open_item(master_key, &item.id, &ct, &nonce)
            .with_context(|| format!("条目 {} 解密失败（master_key 不匹配？）", item.id))?;
        item.plaintext = Some(
            serde_json::from_slice(&plaintext)
                .with_context(|| format!("条目 {} 明文不是合法 JSON", item.id))?,
        );
        out.insert(item.id.clone(), item);
    }
    Ok(out)
}

fn load_seq(dir: &Path) -> Result<i64> {
    let path = dir.join("seq");
    match config::read_optional(&path)? {
        None => Ok(0),
        Some(data) => {
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            if text.is_empty() {
                return Ok(0);
            }
            text.parse::<i64>()
                .with_context(|| format!("seq 文件内容非法: {text}"))
        }
    }
}

fn save_seq(dir: &Path, seq: i64) -> Result<()> {
    config::write_private(&dir.join("seq"), seq.to_string().as_bytes())
}

fn sanitize_id(id: &str) -> String {
    if !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return id.to_string();
    }
    let digest = crypto::sha256(id.as_bytes());
    format!("item-{}", &crypto::hex_encode(&digest)[..16])
}

// ---------------------------------------------------------------------------
// CTAP2 backend
// ---------------------------------------------------------------------------

/// 把本地条目适配为 CTAP2 authenticator 的凭据后端。
pub struct StoreBackend {
    store: Arc<Mutex<LocalStore>>,
    notifier: Arc<dyn ChangeNotifier>,
}

impl StoreBackend {
    /// 构造 backend；`notifier` 用于触发后台同步。
    pub fn new(store: Arc<Mutex<LocalStore>>, notifier: Arc<dyn ChangeNotifier>) -> Self {
        Self { store, notifier }
    }

    /// 取出共享的本地存储（selftest / e2e 用）。
    pub fn shared(&self) -> &Arc<Mutex<LocalStore>> {
        &self.store
    }
}

impl CredentialBackend for StoreBackend {
    fn find(
        &self,
        rp_id: &str,
        allow: Option<&[Vec<u8>]>,
        discoverable_only: bool,
    ) -> Result<Vec<CredentialData>> {
        let store = self.store.lock().map_err(|_| anyhow!("本地存储锁中毒"))?;
        let mut out = Vec::new();
        for item in store.items() {
            if item.kind != "webauthn" || item.rp_id != rp_id || item.is_deleted() {
                continue;
            }
            let Some(value) = item.plaintext.as_ref() else {
                continue;
            };
            let Some(cred) = credential_from_value(item.id.clone(), value) else {
                continue;
            };
            if discoverable_only && !cred.discoverable {
                continue;
            }
            if let Some(allow) = allow {
                if !allow.is_empty() && !allow.iter().any(|id| id == &cred.credential_id) {
                    continue;
                }
            }
            out.push(cred);
        }
        Ok(out)
    }

    fn exists(&self, rp_id: &str, credential_ids: &[Vec<u8>]) -> Result<bool> {
        let store = self.store.lock().map_err(|_| anyhow!("本地存储锁中毒"))?;
        for item in store.items() {
            if item.kind != "webauthn" || item.rp_id != rp_id || item.is_deleted() {
                continue;
            }
            let Some(value) = item.plaintext.as_ref() else {
                continue;
            };
            if let Some(cred) = credential_from_value(item.id.clone(), value) {
                if credential_ids.iter().any(|id| id == &cred.credential_id) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn insert(&mut self, new: NewCredential) -> Result<()> {
        let mut store = self.store.lock().map_err(|_| anyhow!("本地存储锁中毒"))?;
        let id = new_item_id()?;
        let now = config::now_unix();
        let value = new_credential_json(&new, &id, now)?;
        store.upsert_plaintext(
            id,
            "webauthn".to_string(),
            new.rp_id.clone(),
            value,
            0,
            0,
            now,
        )?;
        store.save()?;
        drop(store);
        self.notifier.notify_change();
        Ok(())
    }

    fn update_sign_count(&mut self, credential_id: &[u8], sign_count: u32) -> Result<()> {
        let mut store = self.store.lock().map_err(|_| anyhow!("本地存储锁中毒"))?;
        let mut found: Option<String> = None;
        for item in store.items() {
            if item.kind != "webauthn" || item.is_deleted() {
                continue;
            }
            let Some(value) = item.plaintext.as_ref() else {
                continue;
            };
            if let Some(cred) = credential_from_value(item.id.clone(), value) {
                if cred.credential_id == credential_id {
                    found = Some(item.id.clone());
                    break;
                }
            }
        }
        let id = found.ok_or_else(|| anyhow!("找不到 credential_id 对应的本地条目"))?;
        store.mutate_plaintext(&id, |value| {
            value["sign_count"] = json!(sign_count);
            value["updated_at"] = json!(config::now_unix());
            Ok(())
        })?;
        store.save()?;
        drop(store);
        self.notifier.notify_change();
        Ok(())
    }
}

/// 从明文 JSON 提取凭据。
fn credential_from_value(item_id: String, value: &Value) -> Option<CredentialData> {
    let rp_id = value.get("rp_id")?.as_str()?.to_string();
    let credential_id = crypto::b64_decode(value.get("credential_id")?.as_str()?).ok()?;
    let private_key_der = crypto::b64_decode(value.get("private_key")?.as_str()?).ok()?;
    let user_handle = value
        .get("user_handle")
        .and_then(|v| v.as_str())
        .and_then(|s| crypto::b64_decode(s).ok())
        .unwrap_or_default();
    let username = value
        .get("username")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let display_name = value
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let sign_count = value
        .get("sign_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let discoverable = value
        .get("discoverable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(CredentialData {
        item_id,
        rp_id,
        user_handle,
        credential_id,
        username,
        display_name,
        private_key_der: Zeroizing::new(private_key_der),
        sign_count,
        discoverable,
    })
}

/// 构造 webauthn 条目明文（保留与 shared/examples/item-webauthn.json 相同字段）。
fn new_credential_json(new: &NewCredential, item_id: &str, now: i64) -> Result<Value> {
    let label = new
        .username
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(new.rp_name.as_deref().filter(|s| !s.is_empty()))
        .unwrap_or(&new.rp_id)
        .to_string();
    Ok(json!({
        "kind": "webauthn",
        "label": label,
        "rp_id": &new.rp_id,
        "rp_name": &new.rp_name,
        "user_handle": crypto::b64_encode(&new.user_handle),
        "username": &new.username,
        "display_name": &new.display_name,
        "credential_id": crypto::b64_encode(&new.credential_id),
        "alg": -7,
        "private_key": crypto::b64_encode(&new.private_key_der),
        "sign_count": new.sign_count,
        "transports": ["internal"],
        "discoverable": new.discoverable,
        "notes": format!("vkey 自动创建（item {item_id}）"),
        "created_at": now,
        "updated_at": now,
    }))
}

/// 从目录加载并返回本地存储（main / selftest 便利函数）。
pub fn open_store(dir: &Path, master_key: Zeroizing<Vec<u8>>) -> Result<LocalStore> {
    LocalStore::load(dir, master_key)
}

/// 读取文件系统上的条目数（无需解锁）。
pub fn disk_item_count(dir: &Path) -> Result<usize> {
    count_items_on_disk(dir)
}
