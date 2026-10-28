# vkey Android 并发契约（ASYNC）

本文件登记 `android/` 中所有**异步/并发交互点**：共享状态、保护手段、顺序契约、位置。
新增或修改并发逻辑必须同批更新本文件（`server/ASYNC.md` 管 vkeyd 侧）。

## 总览

- Compose UI 在 **main** 线程组合/绘制；网络与磁盘在 **`Dispatchers.IO`**。
- 跨线程只经两条通道：`@Composable` 的 `mutableStateOf`（Compose 快照，单写者 main）
  与 `FaviconCache`/`FaviconFetcher`（下表的显式同步）。

## 交互点

| # | 交互点 | 共享状态 | 保护手段 | 顺序契约 | 位置 |
|---|---|---|---|---|---|
| 1 | 图标内存缓存 | `FaviconMemoryCache.values`（LRU）+ `failures` | 实例级 `@Synchronized`（所有方法串行） | 只有加载成功后 `put`；`put` 顺带清除该域名失败记录 | `app/src/main/java/dev/xiaoqiong/vkey/net/FaviconCache.kt` |
| 2 | 图标磁盘缓存 | `cacheDir/icons/<sha1>.png` | 仅 IO 线程读写；main 只做 `stat` 判新鲜度 | 先写文件再 `put` 内存；过期/解码失败即删除 | `net/FaviconFetcher.kt:load` / `:hasCached` |
| 3 | 图标首帧状态 | `IssuerIcon` 的 `favicon` / `awaitingDisk` | Compose 快照（UI 单写者） | 首帧同步判定（内存 → 磁盘 stat → 字母），随后唯一一次 `LaunchedEffect` 覆盖 | `app/src/main/java/dev/xiaoqiong/vkey/ui/IssuerIcon.kt` |

## 不变量

1. **`peek`/`isFailed` 不得做 IO**：main 线程每次重组都会调用，任何阻塞都会掉帧。
2. **失败静默期 6 小时**：`markFailed` 只由「所有候选路径都失败」的加载路径调用，
   不得因域名非法/已在静默期而调用（否则会不断续期）。
3. **内存缓存不持有过期磁盘数据**：磁盘 TTL（7 天）到期后，进程重启即失效；
   进程内命中的内存项不做过期判断（图标内容不敏感、体积小）。
4. **同域并发加载允许重复**：不做请求去重；`put` 幂等，后写覆盖先写。

## 已知边界

- `failures` 是进程内 Map：杀进程后负缓存丢失（磁盘 `.fail` 标记未实现，按需再加）。
- LRU 上限按**条目数**（64），不按字节；单个 Bitmap 尺寸由站点图标决定（上限 200KB 字节）。
