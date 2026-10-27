//! 增量同步与 LWW 冲突处理。
//!
//! 顺序：先推送本地 dirty 条目（`POST /items`），再按 `seq` 增量拉取
//! （`GET /items?since=`）。冲突条目会写成
//! `conflicts/<id>.conflict-<ts>.json`（只含密文），然后重新拉取该条。
//!
//! 并发契约（对应项目 `docs/ASYNC.md` 的要求，本仓库不改 docs/）：
//! - `LocalStore` 由 `Arc<Mutex<..>>` 保护；
//! - 网络请求在锁外进行，锁内只做快照与结果应用；
//! - 后台线程 30s 或被 `SyncTrigger` 唤醒时同步一次。

use crate::api::{ApiClient, Auth, PushResult};
use crate::ctap2::authenticator::{ChangeNotifier, NoopNotifier};
use crate::store::LocalStore;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// 单次同步结果。
#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    /// 服务端成功应用的推送条数。
    pub pushed: usize,
    /// 拉取的线上条目数（含墓碑）。
    pub pulled: usize,
    /// LWW 冲突/拒绝条数。
    pub conflicts: usize,
    /// 同步后的本地 seq。
    pub seq: i64,
    /// 是否发生过服务端回滚后的全量重拉。
    pub full_reload: bool,
}

impl SyncReport {
    pub fn changed(&self) -> bool {
        self.pushed > 0 || self.pulled > 0 || self.conflicts > 0 || self.full_reload
    }
}

/// 同步引擎（单线程阻塞）。
pub struct SyncEngine {
    client: ApiClient,
    auth: Auth,
}

impl SyncEngine {
    pub fn new(client: ApiClient, auth: Auth) -> Self {
        Self { client, auth }
    }

    /// 同步共享的本地存储。
    pub fn sync_shared(&self, store: &Arc<Mutex<LocalStore>>) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        // 1) 快照 dirty 条目并在锁外推送。
        let dirty = {
            let mut s = lock(store)?;
            s.save()?;
            s.dirty_items()?
        };
        let results = if dirty.is_empty() {
            Vec::new()
        } else {
            let results = self.client.post_items(&self.auth, &dirty)?;
            report.pushed = results.iter().filter(|r| r.status == "applied").count();
            results
        };

        // 2) 应用推送结果；冲突条目写本地副本并重新拉取。
        let reload_ids = {
            let mut s = lock(store)?;
            s.apply_push_results(&results)?
        };
        report.conflicts = reload_ids.len();
        if !reload_ids.is_empty() {
            let versions: HashMap<&str, i64> = results
                .iter()
                .map(|r: &PushResult| (r.id.as_str(), r.version))
                .collect();
            for id in &reload_ids {
                let version = versions.get(id.as_str()).copied().unwrap_or(0);
                self.pull_one(store, id, version, &mut report)?;
            }
        }

        // 3) 增量拉取（处理服务端回滚）。
        let mut since = lock(store)?.seq();
        let mut loops = 0usize;
        loop {
            loops += 1;
            if loops > 200 {
                return Err(anyhow!("增量拉取循环超过 200 次，疑似服务端 next 异常"));
            }
            let page = self.client.get_items(&self.auth, since)?;
            let mut s = lock(store)?;
            if page.next < since {
                // 服务端版本回滚（备份恢复等）：全量重拉。
                s.reset_for_full_reload()?;
                report.full_reload = true;
                drop(s);
                since = 0;
                continue;
            }
            s.apply_pull(&page)?;
            report.pulled += page.items.len();
            since = s.seq();
            let done = page.items.len() < 1000;
            drop(s);
            if done {
                break;
            }
        }
        report.seq = since;
        Ok(report)
    }

    /// 冲突后定向重拉一条（`since=version-1`），确保本地与服务端一致。
    fn pull_one(
        &self,
        store: &Arc<Mutex<LocalStore>>,
        id: &str,
        version: i64,
        report: &mut SyncReport,
    ) -> Result<()> {
        if version <= 0 {
            // 服务端不存在该条（base_version 不匹配），本地副本已落 conflict 文件。
            return Ok(());
        }
        let page = self
            .client
            .get_items(&self.auth, version.saturating_sub(1))?;
        let mut s = lock(store)?;
        for wire in &page.items {
            if wire.id == id {
                s.apply_wire_item(wire)?;
                report.pulled += 1;
            }
        }
        s.save()?;
        Ok(())
    }
}

/// 后台同步触发器。
pub struct SyncTrigger {
    tx: mpsc::Sender<()>,
}

impl ChangeNotifier for SyncTrigger {
    fn notify_change(&self) {
        let _ = self.tx.send(());
    }
}

impl SyncTrigger {
    /// 启动后台线程：每 30s 或收到变更通知时同步一次。
    pub fn spawn(store: Arc<Mutex<LocalStore>>, client: ApiClient, auth: Auth) -> Self {
        let (tx, rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let engine = SyncEngine::new(client, auth);
            while let Ok(()) | Err(RecvTimeoutError::Timeout) =
                rx.recv_timeout(Duration::from_secs(30))
            {
                match engine.sync_shared(&store) {
                    Ok(r) if r.changed() => eprintln!(
                        "vkey-hid: 同步完成 pushed={} pulled={} conflicts={} seq={}",
                        r.pushed, r.pulled, r.conflicts, r.seq
                    ),
                    Ok(_) => {}
                    Err(e) => eprintln!("vkey-hid: 后台同步失败: {e:#}"),
                }
            }
        });
        Self { tx }
    }
}

/// 一次性同步（CLI / selftest 用；不启动后台线程）。
///
/// 返回同步后的存储与报告（存储通过 Arc<Mutex> 在引擎内部短暂共享）。
pub fn sync_once(
    client: &ApiClient,
    auth: &Auth,
    store: LocalStore,
) -> Result<(LocalStore, SyncReport)> {
    let shared = Arc::new(Mutex::new(store));
    let engine = SyncEngine::new(client.clone(), auth.clone());
    let report = engine.sync_shared(&shared)?;
    let mutex =
        Arc::try_unwrap(shared).map_err(|_| anyhow!("同步后仍存在本地存储引用，无法取回"))?;
    let store = mutex.into_inner().map_err(|_| anyhow!("本地存储锁中毒"))?;
    Ok((store, report))
}

/// 不触发同步的通知器（selftest 用）。
pub fn noop_trigger() -> Arc<dyn ChangeNotifier> {
    Arc::new(NoopNotifier)
}

fn lock(store: &Arc<Mutex<LocalStore>>) -> Result<std::sync::MutexGuard<'_, LocalStore>> {
    store.lock().map_err(|_| anyhow!("本地存储锁中毒"))
}
