# vkeyd 并发契约（ASYNC）

本文件登记 vkeyd 中所有**异步/并发交互点**：共享状态、保护手段、顺序契约、位置。
新增或修改并发逻辑必须同批更新本文件。

> 说明：仓库根 `docs/` 由用户维护（本期禁止写入），因此本清单落在
> `server/ASYNC.md`。

## 总览

vkeyd 是「单进程 + 单 sqlite 连接 + 同步处理函数」的模型：没有后台任务、
没有 worker pool，唯一显式 goroutine 是 HTTP 监听。

| # | 交互点 | 共享状态 | 保护手段 | 顺序契约 | 位置 |
|---|---|---|---|---|---|
| 1 | sqlite 访问 | `*sql.DB` 连接池 | `SetMaxOpenConns(1)` + `busy_timeout=5000` | 所有 SQL 串行；事务提交顺序即可见顺序 | `internal/store/store.go:Open` |
| 2 | per-user seq | `meta` 行 `seq:<user_id>` | 读-改-写在**同一事务**内完成 | 同一事务内多次 applied 连续占号；并发写按事务串行化 | `internal/store/items.go:ApplyItems` |
| 3 | 条目 LWW | `items` + `item_conflicts` | 同上（单事务 + 单连接） | 先比较再写，冲突副本与主行同事务落库 | `internal/store/items.go:applyOne` |
| 4 | 配对码消费 | `pairs.used_at` + `devices` 新行 | 单事务 + `UPDATE ... WHERE used_at IS NULL` + `code_hash` 唯一索引 | 恰好一个并发请求能把 `used_at` 从 NULL 改为非 NULL；失败者回滚并返回 409 | `internal/store/pairs.go:ClaimPair` |
| 5 | 设备 upsert / token 轮换 | `devices.token_hash`（单槽） | 单事务 + `devices(token_hash)` 唯一部分索引 | 同公钥并发认证时后提交者覆盖 token，先提交者的 token 失效；不会出现两条同公钥活跃设备 | `internal/store/devices.go:UpsertDevice` |
| 6 | 限流计数 | `rateLimiter.buckets` | `sync.Mutex` | 固定窗口；窗口切换在锁内判定；桶数超 4096 时锁内清理过期项 | `internal/api/ratelimit.go` |
| 7 | HTTP 生命周期 | `http.Server` + `errCh` | `signal.NotifyContext` + 单写单读 channel | `ListenAndServe` 在独立 goroutine；主 goroutine 二选一（监听错误 / 退出信号），随后 `Shutdown(10s)` | `cmd/vkeyd/main.go:runServe` |
| 8 | 鉴权时 `last_seen` | `devices.last_seen` | sqlite 串行 | 每次通过鉴权的请求同步写一次；失败只记日志，不影响请求 | `internal/api/api.go:authenticate` |
| 9 | 时钟来源 | `Options.Now`（默认 `time.Now`） | 构造时固定函数值 | 测试可注入；业务代码不得直接调用 `time.Now` 做协议判定 | `internal/api/api.go:New` |
| 10 | 开户码消费（enroll） | `enroll_codes.used_at/revoked_at` + `users` + `devices` 新行 | 单事务 + `UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL` 条件更新 + `code_hash` 唯一索引 | 恰好一个并发请求能把 `used_at` 从 NULL 改为非 NULL；失败者回滚（不残留用户/设备），统一返回 invalid_code | `internal/store/enroll.go:Enroll` |
| 11 | 配额判定 | `meta` 中 `quota.*` 键 + `items/devices` 计数 | 设备/条目配额在**写事务内**计数判定（`checkDeviceSlot` / `checkItemQuota`）；配额值本身在事务外预读 | 超限整批回滚（不部分生效）；「读配额值」与「写事务」之间的配置修改允许一个请求窗口内不一致（运维改配置非协议事件） | `internal/store/store.go`、`internal/store/items.go`、`internal/store/devices.go`、`internal/store/pairs.go` |
| 12 | 停用判定 | `users.disabled_at` | 只读，无写竞争 | `authenticate` 与 `auth/token`、`pair/claim` 每次请求实时读取：disable 生效不需要进程内状态变更 | `internal/api/api.go:authenticate`、`internal/store/pairs.go:ClaimPair` |
| 13 | items 主键迁移 | 连接级 `PRAGMA foreign_keys`（OFF→迁移→ON） | 仅在 `Open` 阶段执行（进程尚未开始服务）；`SetMaxOpenConns(1)` 保证 BEGIN/DDL/COMMIT 落在同一连接 | `PRAGMA foreign_keys=OFF` 必须在 `BEGIN IMMEDIATE` 之前（事务内该 PRAGMA 是 no-op）；失败即 ROLLBACK 并恢复 ON；重复打开已迁移库直接跳过（`PRAGMA table_info` 判定） | `internal/store/store.go:migrateItemsPK` |

## 不变量

1. **`version` 只增不减、账号内唯一**：任何写入路径都必须先 `seqGet`、再 `++`、
   同事务 `seqPut`；禁止在事务外分配版本号。
2. **配对码 / 开户码最多成功消费一次**：不得把「查 `used_at`」和「写 `used_at`」拆成两个事务。
3. **同一设备最多一个有效 token**：`token_hash` 是单列；不要新增多 token 表而不更新协议。
4. **请求内不做后台异步写**：审计、`last_seen` 都是同步写，避免进程退出时丢事件。
5. **错误路径必须回滚**：所有事务都 `defer tx.Rollback()`，提交失败不得返回成功。

## 已知边界

- 单连接意味着长查询会阻塞所有请求。当前所有查询都有索引且数据量在单用户量级
  （`items(user_id, version)`、`devices(token_hash)`、`pairs(code_hash)`）。
- 若未来引入多进程/多实例共享同一 sqlite 文件，`busy_timeout` 只能缓解而无法
  保证 `ClaimPair` 的跨进程互斥——必须改为数据库唯一约束驱动的原子更新，或换
  postgres（设计文档 §4.1 的可选项）。
- 限流是**进程内**计数，重启清零；多实例部署时不共享，需要移到 nginx/网关层。
- 未使用 `-race` 的 CI 门禁；本地可用 `go test -race ./...`（需要 C 工具链，
  Windows 上未必可用）。

## 测试覆盖

- `internal/api/e2e_test.go`：配对 → 设备 B 认证 → 写入 → 拉取 → 解密。
- `internal/api/auth_test.go`：token 轮换、吊销、时钟偏移、篡改 body。
- `internal/api/items_test.go`：LWW 三分支、墓碑、8 KiB 上限。
- `internal/api/pair_test.go`：单次可用、过期 410、二次 409。
- `internal/store/enroll_test.go`：开户码生命周期（正常/过期/撤销/用户名占用/未绑定）、
  同一开户码 8 路并发仅一个成功、旧库补列迁移、级联删除与 dry-run 一致性。
- `internal/store/migration_test.go`：items 全局主键 → 复合主键 `(user_id, id)` 的
  12 步表重建（行数/数据不变、跨用户同名 id 可写、索引保留、重复打开幂等、日志不含内容）。
- `internal/store/quota_test.go`：三档配额的存储层语义（整批回滚、幂等路径不占额、
  超限时配对码不被消费）。
- `internal/api/enroll_test.go`：enroll 契约（200/400/403/409/410/429）、token 语义、
  跨租户隔离（同名条目互不可见、跨账号吊销 404）、disable 全链路 401。
