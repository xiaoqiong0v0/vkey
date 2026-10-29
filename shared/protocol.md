# vkey 协议契约（v0.1 / M1）

本文件是 **Go 服务端、Rust/Linux daemon、Android 客户端共享的唯一权威契约**。
任何实现都必须与本文逐字节一致；`shared/vectors/*.json` 是用于交叉验证的测试向量
（由 `server/cmd/genvectors` 生成，见 §9）。

- 状态：M1 第一块（服务端 + 同步协议）已实现并冻结
- 适用版本：`vkeyd 0.1.0-m1`
- 服务端零知识：**master_key 永不上传**；服务端只见 verifier、密文与元数据

术语：`UTF8(x)` 表示字符串 x 的 UTF-8 字节序列（不做任何 Unicode 归一化）；
`||` 表示字节串拼接；`SHA256`、`HMAC-SHA256`、`AES-256-GCM` 均为标准算法。

---

## 1. 算法常量表

| 项 | 值 |
|---|---|
| master_key | 32B 随机，账号级，永不上传 |
| verifier | `HKDF-SHA256(ikm=master_key, salt=UTF8("vkey-verifier"), info=UTF8(username), len=32)` |
| item_key | `HKDF-SHA256(ikm=master_key, salt=UTF8("vkey-item"), info=UTF8(item_id), len=32)` |
| 条目 AEAD | AES-256-GCM，nonce 12B 随机，AAD=`UTF8("vkey-item|"+item_id)` |
| 主密码 KEK | `Argon2id(pw, pw_salt=16B随机, m=65536KiB, t=3, p=1, len=32)`；`wrapped_key=AES-256-GCM(KEK, nonce=12B随机, master_key)`，存服务端 |
| 配对 KEK | `HKDF-SHA256(ikm=code_bytes, salt=UTF8("vkey-pair"), info=UTF8(code_id), len=32)`；`blob=AES-256-GCM(KEK, nonce=12B随机, master_key)` |
| 设备密钥 | Ed25519 |
| 设备 token | 32B 随机，服务端只存 `SHA256(token)` |
| 编码 | 二进制字段一律 base64url 无填充；`master_key` 展示用 base32 无填充大写；配对码为 32B 随机 → base32 无填充，展示按 4 字符分组用 `-` 连接 |

补充规定（上表未覆盖但实现必须一致的细节）：

| 项 | 规定 |
|---|---|
| HKDF | RFC 5869，PRK=`HMAC-SHA256(salt, ikm)`，OKM 取 expand 前 32B；salt/info 就是表中的 UTF-8 字节，不做长度截断或补零 |
| 条目密文 | `AES-256-GCM` 输出（**含 16B tag**）；线上拆成 `ct` 与 `nonce` 两个字段，`ct` 不含 nonce |
| wrapped_key / pair blob | **自包含布局**：`nonce(12B) || AES-256-GCM 输出(含 tag)`；无 AAD（见 §10 偏差 2） |
| Ed25519 公钥 | 32B 原始公钥（不带 SPKI 头） |
| Ed25519 签名 | 64B 原始签名，HTTP 头上用 base64url 无填充 |
| token_hash | `SHA256(token 原始 32B)`，32B |
| code_hash | `SHA256(配对码原始 32B)`（不是 SHA256(展示字符串)） |
| base32 | RFC 4648 标准字母表 `A-Z2-7`，大写，无 `=` 填充 |
| base64url | RFC 4648 §5，`-`/`_` 字母表，无 `=` 填充 |
| 时间 | 全部为 int64 unix 秒（UTC） |

### 1.1 派生计算式（逐字节）

```
verifier  = HKDF-SHA256(ikm=master_key,
                        salt=bytes("vkey-verifier"),
                        info=bytes(username),
                        L=32)

item_key  = HKDF-SHA256(ikm=master_key,
                        salt=bytes("vkey-item"),
                        info=bytes(item_id),
                        L=32)

item_aad  = bytes("vkey-item|") || bytes(item_id)

ct        = AES-256-GCM-Seal(key=item_key, nonce=nonce12, plaintext=item_json_utf8, aad=item_aad)

kek_pw    = Argon2id(password=bytes(pw), salt=pw_salt16,
                     m=65536 (KiB), t=3, p=1, L=32)
wrapped   = nonce12 || AES-256-GCM-Seal(key=kek_pw, nonce=nonce12, plaintext=master_key, aad=∅)

kek_pair  = HKDF-SHA256(ikm=code_bytes32,
                        salt=bytes("vkey-pair"),
                        info=bytes(code_id),
                        L=32)
blob      = nonce12 || AES-256-GCM-Seal(key=kek_pair, nonce=nonce12, plaintext=master_key, aad=∅)

token_hash = SHA256(token32)
code_hash  = SHA256(code_bytes32)
```

`item_json_utf8` 是 §5 定义的条目明文 JSON 的 UTF-8 序列化。客户端可以自行决定
JSON 字段顺序与空白；服务端不解密，因此不校验明文结构。

### 1.2 配对码编码

- 原始值：32B 随机（`code_bytes`）。
- 线上规范形式：`base32(code_bytes)`，大写、无填充、**无分组符**。
- 人类展示形式：在规范形式上每 4 个字符插入一个 `-`。32B 编码为 52 个字符，
  因此展示为 13 组、形如 `AAAA-BBBB-CCCC-...`。
- 解析输入（客户端输入框、`pair/new`、`pair/claim`）必须容忍：小写、`-`、
  空格、制表符、换行、`=` 填充；解析后必须恰好 32B。

`master_key` 的 base32 解析规则相同（容忍同样字符），但展示形式不加 `-`。

---

## 2. 传输与编码约定

- 协议为 HTTPS + JSON（TLS 在 nginx 终止；明文仅允许出现在回环监听）。
- 请求/响应 `Content-Type: application/json; charset=utf-8`。
- 所有 JSON 字段名区分大小写，采用 `snake_case`。
- 二进制字段（`ct`、`nonce`、`verifier`、`pubkey`、`token`、`blob`、`pw_salt`、
  `wrapped_key`、`signature` 等）在 JSON/HTTP 头中一律 base64url 无填充。
- 未识别字段：服务端忽略（向前兼容）；客户端必须保留条目明文中的未知字段。
- 数值：时间/版本均为 JSON number（int64）；客户端不得传浮点。

### 2.1 错误响应

所有 API 错误统一为：

```json
{"error": {"code": "machine_readable_code", "message": "人类可读说明"}}
```

HTTP 状态码同时置为对应值。错误码清单：

| HTTP | code | 含义 |
|---|---|---|
| 400 | `invalid_json` / `empty_body` | 请求体缺失或不是合法 JSON |
| 400 | `invalid_item` / `item_too_large` / `too_many_items` | 条目结构非法 / 密文超 8 KiB / 单次超 500 条 |
| 400 | `invalid_*` | 其它字段校验失败（如 `invalid_code`、`invalid_pubkey`、`invalid_since`） |
| 401 | `missing_token` / `invalid_token` | 缺少/无效 Bearer token（含设备已吊销） |
| 401 | `missing_ts` / `invalid_ts` / `ts_skew` | 时间戳缺失/非法/超出 ±120 秒 |
| 401 | `missing_sig` / `bad_signature` | 签名头缺失或校验失败 |
| 401 | `invalid_credentials` | auth/token 的 username 或 verifier 不正确 |
| 404 | `not_found` / `device_not_found` / `code_not_found` | 资源不存在 |
| 405 | `method_not_allowed` | 方法不支持（附 `Allow` 头） |
| 409 | `code_used` / `code_id_exists` | 配对码已用 / code_id 冲突 |
| 410 | `code_expired` | 配对码过期 |
| 413 | `body_too_large` | 请求体超 8 MiB |
| 429 | `rate_limited` | 免鉴权端点限流（附 `Retry-After` 秒数） |
| 500 | `internal` | 服务端内部错误（不泄露细节） |

---

## 3. 鉴权

### 3.1 设备签名串（精确格式）

```
METHOD + "\n"
+ RequestURI + "\n"
+ hex_lowercase(SHA256(request_body)) + "\n"
+ decimal(unix_seconds)
```

- `METHOD`：HTTP 方法原文，大写（`GET`/`POST`）。
- `RequestURI`：客户端请求行里的原始 target，**必须包含 query**，
  不含 scheme/host，不做任何重新编码或排序。例如 `/api/v1/items?since=42`。
- `request_body`：发送的原始字节。GET 等无 body 请求视为空字节串，
  即 `SHA256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。
- `decimal(unix_seconds)`：与 `X-Vkey-Ts` 完全相同的十进制字符串（无前导零）。
- 各部分之间只有单个 `\n`（0x0A），末尾无换行。

签名：`Ed25519-Sign(device_private_key, signing_string)`，得到 64B。

### 3.2 请求头

```
Authorization: Bearer <base64url(token 32B)>
X-Vkey-Ts: <unix 秒，十进制>
X-Vkey-Sig: <base64url(64B Ed25519 签名)>
```

服务端校验顺序：token 格式 → `|now - ts| <= 120` → `SHA256(token)` 查未吊销设备
→ 用设备公钥验签。任一步失败返回 401；已吊销设备视同未知 token。

### 3.3 token 生命周期

- token 为 32B 随机值，服务端只保存 `SHA256(token)`，明文 token 只在签发给客户端时出现一次。
- `devices` 表每个设备只有一个 `token_hash` 槽位：同一设备（同公钥、未吊销）再次调用
  `auth/token` 会覆盖旧值 → **旧 token 立即失效**（见 §10 偏差 7）。
- `devices/revoke` 会清空 `token_hash` 并写 `revoked_at`，此后该 token 与设备永久失效。
- 设备身份 = Ed25519 公钥；设备 id 是服务端生成的 16B 随机数 base64url（22 字符）。
- 已知限制：同一签名在 ±120 秒窗口内可被重放。写接口依靠 LWW 与唯一键
  （`code_id`/`code_hash`/`token_hash`）天然去重；客户端不应依赖服务端做请求级防重放。

---

## 4. HTTP API

基址：`https://<domain>`。下表“鉴权”列中“签名”表示必须携带 §3 的三件套。

### 4.1 `GET /api/v1/policy`（免鉴权）

响应：

```json
{
  "require_master_pw": false,
  "require_master_pw_enforced": false,
  "kdf": {"m": 65536, "t": 3, "p": 1},
  "username_hint": "default"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `require_master_pw` | bool | 服务端策略：是否要求客户端启用主密码包裹层 |
| `require_master_pw_enforced` | bool | **实际可执行性**：`require_master_pw && users.wrapped_key IS NOT NULL`。为 `true` 时客户端必须用主密码解包；`require_master_pw=true` 但本字段为 `false` 时，客户端必须报错并提示先执行 `vkey-hid passwd`，**不得静默回退**到 `local.key` |
| `kdf` | object | Argon2id 参数（KiB / 迭代 / 并行度），固定为 65536/3/1 |
| `username_hint` | string | 唯一账号的**原始用户名**，用于预填登录框。verifier 的 HKDF info 就是该字符串，客户端必须拿到精确值；尚未 init 时为空串 |

客户端每次启动必须重新查询，本地缓存不得覆盖服务端策略。

### 4.2 `GET /api/v1/health`（免鉴权）

```json
{"status": "ok", "version": "0.1.0-m1", "items": 12, "devices": 3}
```

`items` 只统计未删除条目；`devices` 只统计未吊销设备。

### 4.3 `POST /api/v1/auth/token`（免鉴权，限流 60 次/分钟/IP）

请求：

```json
{
  "username": "default",
  "verifier": "base64url(32B)",
  "device": {"name": "desk-linux", "platform": "linux", "pubkey": "base64url(32B)"}
}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `username` | string | 1..128 字节，必须与 init 时一致 |
| `verifier` | string | base64url，解码后 32B |
| `device.name` | string | 1..128 字节 |
| `device.platform` | string | 1..32 字节（`linux`/`windows`/`android`/`browser`…） |
| `device.pubkey` | string | base64url，解码后 32B Ed25519 公钥 |

响应（可选字段不存在时省略）：

```json
{
  "token": "base64url(32B)",
  "device_id": "base64url(16B)",
  "pw_salt": "base64url(16B)",
  "wrapped_key": "base64url(nonce||ct||tag)"
}
```

语义：

1. 按 `username` 查账号，`verifier` 与库中值做**常量时间比较**；不匹配或用户不存在
   一律 `401 invalid_credentials`（不区分，避免枚举）。
2. 以 `device.pubkey` 在该账号下 upsert 未吊销设备：命中则更新
   `name`/`platform`/`token_hash`/`last_seen`；未命中则新建。
3. 返回新 token；`pw_salt` / `wrapped_key` 来自 `users` 表，由 §4.4 写入（`wrapped_key` 布局为
   `nonce(12)||ciphertext||tag`，与 §1 一致），未写入时省略。
4. 写审计 `auth.token`。

错误：400 `invalid_json`/`invalid_username`/`invalid_verifier`/`invalid_pubkey`/`invalid_device`；
401 `invalid_credentials`；413 `body_too_large`；429 `rate_limited`。

### 4.4 `POST /api/v1/auth/password`（签名）

写入主密码包裹，让策略 `require_master_pw=true` 真正可执行（服务端只存密文，无法解出 `master_key`）。

请求：

```json
{
  "wrapped_key": "base64url(nonce(12)||ct||tag)",
  "pw_salt": "base64url(16B)"
}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `wrapped_key` | string | base64url；解码后为 `nonce(12)||ciphertext||tag` 自包含布局，长度 29..80 字节（32B `master_key` 时为 60 字节） |
| `pw_salt` | string | base64url；解码后必须 16 字节 |

语义：

1. 用签名身份（device）所属账号写入 `users.wrapped_key` / `users.pw_salt`（覆盖旧值）。
2. 写审计 `auth.password.set`。
3. 响应 `{"ok": true}`。
4. 写入后 `GET /policy` 的 `require_master_pw_enforced` 立即变为 `true`（若策略本来为 `true`）。

错误：400 `invalid_json`/`invalid_pw_salt`/`invalid_wrapped_key`；401（§3 鉴权错误）；413 `body_too_large`。

### 4.5 `DELETE /api/v1/auth/password`（签名）

清空主密码包裹（两列同时置 `NULL`）。为防止误删导致其它未持有 `local.key` 的设备**永久无法解密**，
请求体必须显式确认：

```json
{"confirm": "remove-master-password"}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `confirm` | string | 必须精确等于 `remove-master-password`，否则 400 |

语义：

1. 清空 `users.wrapped_key` / `users.pw_salt`。
2. 写审计 `auth.password.clear`。
3. 响应 `{"ok": true}`。此后 `require_master_pw_enforced` 变为 `false`；若 `require_master_pw` 仍为
   `true`，客户端按 §4.1 必须拒绝启动并提示先重新执行 `vkey-hid passwd`。

错误：400 `invalid_json`/`invalid_confirm`；401（§3 鉴权错误）；413 `body_too_large`。

### 4.6 `POST /api/v1/items`（签名）

请求：

```json
{
  "items": [
    {
      "id": "01J9Z6Q3R8T5V7X9Y2B4C6D8E0",
      "kind": "totp",
      "rp_id": "example.com",
      "ct": "base64url(密文含 tag)",
      "nonce": "base64url(12B)",
      "base_version": 7,
      "updated_at": 1761436800,
      "deleted_at": 0
    }
  ]
}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `items` | array | 0..500 条 |
| `id` | string | 1..128 字节，账号内唯一；用于派生 item_key，创建后不可变 |
| `kind` | string | `totp` 或 `webauthn`；创建后不可变 |
| `rp_id` | string | 1..255 字节明文；创建后不可变 |
| `ct` | string | base64url，解码后 ≤ 8192B；墓碑可为空串 |
| `nonce` | string | base64url，解码后必须 12B；墓碑可为空串 |
| `base_version` | int | ≥0，客户端认为的服务端当前版本；0 表示“新建” |
| `updated_at` | int | ≥0，客户端写入时间；0 表示由服务端填 now |
| `deleted_at` | int | ≥0，0=未删除；非 0=墓碑（见 §10 偏差 3） |

响应：

```json
{
  "results": [
    {"id": "01J...", "version": 8, "status": "applied"},
    {"id": "01K...", "version": 3, "status": "conflict", "reason": "stale_write"},
    {"id": "01M...", "version": 2, "status": "rejected", "reason": "kind_mismatch"}
  ]
}
```

`results` 与请求 `items` **顺序一一对应**。

校验与失败语义：

- 先整单结构校验；任一条结构非法 → `400`，**整单不写入**（事务前拒绝）。
- 结构合法但语义失败（kind/rp_id 被改写）→ 该条 `status=rejected`，HTTP 仍为 200。
- `ct` 解码后 > 8192B → `400 item_too_large`。
- 非墓碑条目缺 `ct` 或 `nonce` → `400 invalid_item`。

错误：400 `invalid_item`/`item_too_large`/`too_many_items`/`invalid_json`；
401（鉴权）；413 `body_too_large`；500 `internal`。

LWW（last-write-wins）规则：

设服务端该条目当前版本为 `V`、`updated_at` 为 `U`：

1. 服务端不存在该条目：
   - `base_version == 0` → 应用，`version = ++seq`；
   - 否则 → `conflict`，`version = 0`，不落库（服务端无法判断新旧）。
2. 存在且 `base_version == V` → 应用，`version = ++seq`（无条件）。
3. 否则 `updated_at > U` → 应用（`version = ++seq`），**先把旧行拷入 item_conflicts**。
4. 否则（含 `updated_at == U`）→ `conflict`，`version = V`，**把本次写入拷入 item_conflicts**。

`seq` 是 per-user 单调递增计数，存于 `meta` 表键 `seq:<user_id>`，在同一事务内 `++`；
一次批量写入内多条 applied 依次占用连续版本号。

### 4.7 `GET /api/v1/items?since=<int>`（签名）

| 参数 | 类型 | 说明 |
|---|---|---|
| `since` | int | 非负；只返回 `version > since` 的条目。缺省 0 |

响应：

```json
{
  "items": [
    {
      "id": "01J...", "kind": "totp", "rp_id": "example.com",
      "ct": "base64url", "nonce": "base64url",
      "version": 8, "updated_at": 1761436800, "deleted_at": 0
    }
  ],
  "next": 8
}
```

- 按 `version` 升序，单页最多 1000 条。
- **墓碑也返回**（`deleted_at != 0`），客户端据此删除本地副本；墓碑的 `ct`/`nonce` 为空串。
- `next`：本页条数达到 1000 时为本页最后一条的 `version`（还有下一页），否则为
  服务端当前 `seq`。若 `next < since`，说明服务端版本回滚（如从备份恢复），
  客户端应执行一次全量重拉（`since=0`）。
- 错误：400 `invalid_since`/`invalid_json`；401（鉴权）。

### 4.8 `POST /api/v1/devices/register`（签名）

请求：`{"name":"tablet","platform":"android","pubkey":"base64url(32B)"}`

响应：`{"device_id":"base64url(16B)"}`

- 只登记公钥，**不签发 token**。新设备仍必须用 verifier 调用 `auth/token`
  （见 §10 偏差 6）。同账号同公钥的未吊销设备已存在时幂等返回其 id。
- 写审计 `device.register`。
- 错误：400 `invalid_pubkey`/`invalid_device`；401（鉴权）。

### 4.9 `POST /api/v1/devices/revoke`（签名）

请求：`{"device_id":"base64url(16B)"}` → 响应：`{"ok":true}`

- 只能吊销本账号设备；不存在或已吊销 → `404 device_not_found`。
- 吊销当前设备自身也允许（请求完成即失效）。
- 错误：400 `invalid_device`；401（鉴权）；404 `device_not_found`。

### 4.10 `GET /api/v1/devices`（签名）

响应：

```json
{
  "devices": [
    {
      "id": "base64url(16B)", "name": "desk-linux", "platform": "linux",
      "created_at": 1761436800, "last_seen": 1761437400, "current": true
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | 设备 id，base64url(16B) |
| `name` / `platform` | string | 注册/认证时的设备名与平台 |
| `created_at` | int | 设备创建时间（unix 秒） |
| `last_seen` | int | 最近一次签名请求通过的时间（unix 秒） |
| `current` | bool | 是否为发起本次请求的设备（按 token 解析出的设备 id 比对） |

- 只返回本账号**未吊销**设备，按 `last_seen` 降序（同值按 `created_at` 升序）。
- **不返回公钥、token 与 `token_hash`**；已吊销设备不出现在列表中。
- 只读接口，不写审计。
- 错误：401（鉴权）。

### 4.11 `POST /api/v1/pair/new`（签名）

请求：

```json
{
  "code_id": "pair-20261026-demo",
  "code": "base32(32B, 无分组)",
  "blob": "base64url(nonce12||ct||tag)",
  "pw_salt": "base64url(16B)"
}
```

| 字段 | 类型 | 约束 |
|---|---|---|
| `code_id` | string | 1..64 字节，`[A-Za-z0-9._-]`；作为 HKDF info，也作主键 |
| `code` | string | 32B 配对码的 base32 形式（容忍小写/`-`/空格/`=`） |
| `blob` | string | base64url，解码后 29..4096B（nonce+tag+master_key） |
| `pw_salt` | string | 可选，base64url(16B)；启用主密码时一并下发 |

响应：

```json
{"code_id": "pair-20261026-demo", "code": "base32(无分组)", "expires_at": 1761437400}
```

- TTL 600 秒（10 分钟）。
- 服务端只存 `code_hash=SHA256(code_bytes)`、`blob`、`pw_salt`，**不存 code 明文**。
- `code` 必须由请求携带的原因见 §10 偏差 1；响应回显规范形式，便于调用方核对。
- 同一 `code_id` 重复登记 → `409 code_id_exists`。
- 写审计 `pair.new`。
- 错误：400 `invalid_code_id`/`invalid_code`/`invalid_blob`/`invalid_pw_salt`；
  401（鉴权）；409 `code_id_exists`；413 `body_too_large`。

### 4.12 `POST /api/v1/pair/claim`（免鉴权，限流 60 次/分钟/IP）

请求：

```json
{"code": "AAAA-BBBB-...", "name": "phone", "platform": "android", "pubkey": "base64url(32B)"}
```

响应：

```json
{
  "token": "base64url(32B)",
  "device_id": "base64url(16B)",
  "blob": "base64url(nonce12||ct||tag)",
  "pw_salt": "base64url(16B)",
  "wrapped_key": "base64url(nonce12||ct||tag)",
  "code_id": "pair-20261026-demo"
}
```

- 按 `SHA256(code_bytes)` 查找；`code` 解析失败 → `400 invalid_code`。
- 不存在 → `404 code_not_found`；已使用 → `409 code_used`；已过期 → `410 code_expired`。
- 领取在一个事务内完成：创建设备（签发 token，token_hash 落库）→ 标记 `used_at`。
  **单次可用**（并发领取由条件更新保证只有一个成功）。
- `pw_salt` / `wrapped_key` 取自 `users` 表（由 §4.4 写入），任一为空则省略。新设备可用
  `blob` 解出 `master_key`，若策略要求主密码（`require_master_pw_enforced=true`）则必须用
  `wrapped_key` + 主密码解包校验，不得跳过。
- 写审计 `pair.claim`。
- 错误：400 `invalid_code`/`invalid_pubkey`/`invalid_device`；404 `code_not_found`；
  409 `code_used`；410 `code_expired`；413 `body_too_large`；429 `rate_limited`。

### 4.13 页面与脚本（免鉴权）

| 方法/路径 | 说明 |
|---|---|
| `GET /` | 自检页（HTML）：状态、版本、条目数、设备数、策略、服务器地址。**无解密逻辑** |
| `GET /pair` | 配对页（HTML）：配对码输入提示（只读占位）+ APK 下载占位 |
| `GET /join?c=<CODE>` | **开户落地页**（HTML，免鉴权，仅 `user_mode=admin` 有意义）：开户码**有效未使用**时 200，渲染同源二维码、明文开户码、深链 `vkey://enroll?server=<地址>&code=<CODE>` 按钮与下载链接；缺参数 400，非 admin/不存在/已用/已撤销/过期一律 404 + 统一文案「链接无效或已过期」（不区分细节，防枚举）。响应 `Cache-Control: no-store`；**访问日志只记路径不记 query**（开户码在 `?c=` 中）。打开页面不消费开户码 |
| `GET /join/qr.png?c=<CODE>` | 开户二维码 PNG：`image/png` + `Content-Disposition: attachment; filename="vkey-enroll.png"`，内容为落地页同一深链；有效性判定与 `/join` 完全一致（无效时返回同一 4xx 错误页） |
| `GET /install.sh` | Linux 引导脚本：注入 `server_url`、`uname -m` 选择架构、按 `SHA256SUMS` 校验后下载 `/dl/vkey-hid-linux-<x86_64\|aarch64>.tar.gz`、安装二进制、交互输入凭据、写 udev/tmpfiles 与 systemd user unit（`--no-sudo`/`--no-service` 可跳过） |
| `GET /install.ps1` | Windows 引导脚本：注入 `server_url`、探测 `PROCESSOR_ARCHITECTURE`、下载 MSI 占位、写 `%APPDATA%\vkey` 配置 |
| `GET /dl/{name}` | 产物下载（免鉴权，只读）：`name` 必须匹配 `^[A-Za-z0-9._-]+$` 且出现在 `<artifacts-dir>/SHA256SUMS` 里，否则 404（含 `/`、`..`、空名与多段路径）。响应 `application/octet-stream` + `Content-Length` + `Cache-Control: no-cache` |
| `GET /dl/SHA256SUMS` | 产物清单（免鉴权）：`text/plain; charset=utf-8`，格式同 `sha256sum` 输出；目录不存在时 `/dl/*` 一律 404 |

产物命名（`/dl/{name}` 的白名单由 `SHA256SUMS` 决定）：

| 产物 | 状态 |
|---|---|
| `vkey-hid-linux-x86_64.tar.gz` | ✅ 已提供（M1） |
| `vkey-hid-linux-aarch64.tar.gz` | ⏳ 需交叉工具链，未构建时报 404 |
| `vkey-win-<amd64\|arm64>.msi` | ⏳ 占位（M2） |
| `vkey-android.apk` | ⏳ 占位（M3） |

产物由 `server/deploy/` 流程上传到服务端 `--artifacts-dir`（默认 `./artifacts`），目录内必须同时存在 `SHA256SUMS`；缺失时 `/dl/*` 一律 404。

服务器地址来源：启动参数 `--domain` 优先；未设置时按请求 `Host` +
`X-Forwarded-Proto` 推导。取值经字符白名单过滤后才注入脚本。

### 4.14 `GET /api/v1/update/android`（免鉴权，限流 60 次/分钟/IP）

Android 客户端启动时拉取，用来判断是否需要提示升级。响应 200：

```json
{
  "version_code": 30101,
  "version_name": "0.3.2",
  "url": "https://github.com/xiaoqiong0v0/vkey/releases/latest/download/vkey-android.apk",
  "sha256": "3f786850e387550fdab836ed7e6dc881de23001b2b0f4d1ad1e0c1e7b6d4b3f0",
  "size": 8388608,
  "notes": "首个公开版本",
  "source": "github",
  "published_at": 1761437400
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `version_code` | int | 是 | Android versionCode，客户端据此比较是否需要更新 |
| `version_name` | string | 是 | 展示用版本号（如 `0.3.2`） |
| `url` | string | 是 | APK 下载地址，拼接规则见下 |
| `sha256` | string | 是 | APK 的 sha256（64 位小写 hex），客户端下载后**必须**校验 |
| `size` | int | 是 | APK 字节数，`0` 表示未知 |
| `notes` | string | 否 | 发布说明，空值时字段省略 |
| `source` | string | 是 | `github` / `local` |
| `published_at` | int | 是 | 发布时间（unix 秒），`0` 表示未知 |

**204 语义**：`update.version_code` 与 `update.sha256` 任一未配置（含库中还没有任何
`update.*` 键）时返回 **204 No Content、无正文**，客户端视为「暂无更新」，不得当作错误。

`url` 的拼接规则（服务端只按配置拼接字符串，不做可达性检查）：

| `source` | `url` |
|---|---|
| `github`（缺省） | `https://github.com/<repo>/releases/latest/download/<asset>`，`repo` 缺省 `xiaoqiong0v0/vkey`、`asset` 缺省 `vkey-android.apk` |
| `local` | `<server_url>/dl/<asset>`，`server_url` 同 §4.13（`--domain` 优先，其次按请求推导）；`/dl/*` 的白名单仍由产物目录的 `SHA256SUMS` 决定 |

- **不访问 GitHub API**：该端点只读本机 meta 表（键见 `server/internal/store/update.go`），
  不发起任何出网请求，也不解压/校验 APK。GitHub Releases 未发布或资产名不符时 `url` 仍照常返回，
  由客户端下载失败自行处理。
- 响应头 `Cache-Control: public, max-age=300`（覆盖 `/api/*` 默认的 `no-store`），
  即配置改动后客户端最多 5 分钟后才看到。
- 非 `GET` → `405 method_not_allowed`（`Allow: GET`）；限流 60 次/分钟/IP，超限 429 `rate_limited`。
- 配置入口：`vkeyd policy set --update-*`（写入）、`vkeyd update show`（查看），见 `server/README.md`。

---

## 5. 条目明文 JSON

`ct` 解密后的明文是 UTF-8 JSON。**服务端不解密、不校验**；以下结构是客户端之间的契约。

公共字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `kind` | string | 是 | `totp` / `webauthn`，必须与外层 `items.kind` 一致 |
| `label` | string | 是 | 列表展示主标题（TOTP: 账号；WebAuthn: 用户名或 RP） |
| `notes` | string | 否 | 备注 |
| `created_at` | int | 否 | unix 秒 |
| `updated_at` | int | 否 | unix 秒（外层 `updated_at` 是同步时钟，可不同） |

客户端必须保留未知字段（往返读写不丢），以便后续版本扩展。

### 5.1 `kind = "totp"`

| 字段 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `issuer` | string | 否 | `""` | 发行方 |
| `secret` | string | 是 | — | base32 大写无填充的共享密钥（RFC 4648） |
| `algorithm` | string | 否 | `SHA1` | `SHA1` / `SHA256` / `SHA512` |
| `digits` | int | 否 | `6` | 6..8 |
| `period` | int | 否 | `30` | 秒，>0 |

**外层 `rp_id` 约定**：`kind = "totp"` 的条目，外层 `items.rp_id` **固定为 `"totp"`**，
不随 `issuer` 变化；三端（Go 服务端、Rust/Linux daemon、Android 客户端）必须一致。

样例：`shared/examples/item-totp.json`

### 5.2 `kind = "webauthn"`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `rp_id` | string | 是 | 依赖方域名，必须与外层 `items.rp_id` 一致 |
| `rp_name` | string | 否 | 展示名 |
| `user_handle` | string | 是 | base64url，WebAuthn user.id 原始字节 |
| `username` | string | 否 | 账号名（展示/检索） |
| `display_name` | string | 否 | 展示名 |
| `credential_id` | string | 是 | base64url，WebAuthn credentialId 原始字节 |
| `alg` | int | 是 | COSE 算法号：`-7`=ES256、`-8`=EdDSA、`-257`=RS256 |
| `private_key` | string | 是 | base64url(PKCS#8 DER)，由客户端在解密后导入 |
| `sign_count` | int | 否 | 断言计数器，每次签名后 +1（服务端不校验） |
| `transports` | array\<string\> | 否 | 如 `["internal"]` |
| `discoverable` | bool | 否 | 是否为可发现凭据（`rk=true` 注册时为 true；缺省 false） |

样例：`shared/examples/item-webauthn.json`

安全要求：私钥只允许在客户端内存中出现；签名后立即清零。禁止在网页/服务端解密。

---

## 6. 数据库结构（服务端）

```sql
users(id TEXT PK, username TEXT UNIQUE, verifier BLOB, pw_salt BLOB, wrapped_key BLOB,
      require_master_pw INTEGER, created_at INTEGER)
devices(id TEXT PK, user_id TEXT, name TEXT, platform TEXT, pubkey BLOB, token_hash BLOB,
        revoked_at INTEGER, created_at INTEGER, last_seen INTEGER)
items(user_id TEXT, id TEXT, kind TEXT, rp_id TEXT, ciphertext BLOB, nonce BLOB,
      version INTEGER, updated_at INTEGER, deleted_at INTEGER, PRIMARY KEY(user_id, id))
item_conflicts(id INTEGER PK AUTOINCREMENT, user_id TEXT, item_id TEXT,
               ciphertext BLOB, nonce BLOB, version INTEGER, updated_at INTEGER)
pairs(code_id TEXT PK, user_id TEXT, code_hash BLOB, blob BLOB, pw_salt BLOB,
      expires_at INTEGER, used_at INTEGER, created_at INTEGER)
audit(id INTEGER PK AUTOINCREMENT, user_id TEXT, device_id TEXT, action TEXT, ts INTEGER)
meta(key TEXT PK, value TEXT)          -- 存 seq 计数，键为 "seq:<user_id>"
```

- `items` 主键是复合的 `(user_id, id)`：item id 由客户端自选，仅在账号内唯一，
  不同账号可复用同一 item id（见 §10 偏差 11）。所有按 id 读写 `items` 的语句必须带 `user_id`。
- `NULL` 与空 BLOB 语义不同：`pw_salt`/`wrapped_key`/`token_hash`/`deleted_at` 用 NULL 表示“无”。
- `item_conflicts.version`：落败的**本次写入**记录其 `base_version`；被替换的**旧行**记录其服务端 `version`。
- 审计 `action` 取值：`auth.token`、`items.apply`、`device.register`、`device.revoke`、
  `pair.new`、`pair.claim`。审计只含元数据。
- 服务端为 `devices(token_hash)`（部分索引）、`items(user_id, version)`、
  `pairs(code_hash)` 建索引。
- sqlite 使用 WAL、`busy_timeout=5000`、`foreign_keys=ON`，连接数固定为 1。

---

## 7. 服务端策略与本机 CLI

```
vkeyd init   --db <path> [--username default] [--master-key <base32>]
vkeyd serve  --db <path> --listen :8080 [--domain <域名>] [--set-require-master-pw=true|false]
vkeyd policy set --db <path> --require-master-pw=<bool>
```

- `init`：建库 + 建唯一账号；`--master-key` 缺省时生成 32B 随机值。
  **stdout 只输出一行** `master_key: <base32 无填充>`，其余信息走 stderr；重复 init 返回非 0。
- `serve`：HTTP 服务。`--set-require-master-pw` 未给出时不修改策略；
  给出时在启动前写入并立即生效。
- `policy set`：修改 `users.require_master_pw`。
- 退出码：0 成功；非 0 失败（错误写 stderr）。

---

## 8. 限流与上限

| 项 | 值 |
|---|---|
| `auth/token` | 60 次/分钟/IP（固定窗口；超限 429） |
| `pair/claim` | 60 次/分钟/IP |
| 请求体 | 8 MiB |
| 单条 `ct`（解码后） | 8192 B |
| 单次写入条数 | 500 |
| 单页拉取条数 | 1000 |
| `item.id` | 128 B |
| `rp_id` | 255 B |
| `code_id` | 64 B |
| `blob`（配对） | 4096 B |
| `wrapped_key`（主密码包裹） | 80 B（自包含布局，32B master_key 时 60 B） |
| 配对码 TTL | 600 s |
| 签名时间窗 | ±120 s |

限流的 IP 取 `X-Forwarded-For` 首项，缺失时取连接地址。因此 vkeyd 必须只监听回环，
由可信反向代理写入该头（见 `server/deploy/nginx-vkey.conf`）。

---

## 9. 测试向量

目录：`shared/vectors/`，由 `cd server && go run ./cmd/genvectors` 生成
（也可用 `go test ./internal/crypto -run TestKDFVectors` 重新核对）。

文件与用途：

| 文件 | 向量 |
|---|---|
| `kdf.json` | `verifier`、`item_key`、`pair_kek`、`argon2id_kek` |
| `aead.json` | `item_ciphertext`、`wrapped_key`、`pair_blob` |
| `signing.json` | 3 组签名串 + Ed25519 签名（GET with query / POST / POST） |
| `encoding.json` | master_key 的 base32/base64url、配对码 base32/展示/哈希 |

格式：

```json
{
  "generated_by": "server/cmd/genvectors",
  "vectors": [
    {"name": "...", "inputs": {...}, "expected": {...}}
  ]
}
```

字段命名约定：`*_hex` 为十六进制输入；`*_b64url` 为 base64url 无填充；`*_utf8` 为
原文字符串；`*_b32` / `b32_nopad_upper` 为 base32 大写无填充。所有比较都要求**字节完全相等**。
测试向量中的 nonce/salt 是固定的（实现本身必须使用随机 nonce），固定值只用于跨端复现。

---

## 10. 偏差记录（实现时发现的原契约缺口）

以下是 `docs/design.md` §4.3 的原始 API 列表在落地时发现的不自洽之处，以及本契约的裁定。
**这些裁定已冻结**；任何端实现都必须按本节执行。

1. **`pair/new` 必须携带 `code`**。原接口只列了 `{code_id, blob, pw_salt?}`，但服务端要存
   `code_hash=SHA256(code)`（`pairs.code_hash`），不收到 code 就无法计算；同时 `blob` 由客户端
   用 code 派生 KEK 生成，服务端也不可能自己生成 code。故请求增加必填 `code`，响应回显规范形式。
2. **`wrapped_key` 与配对 `blob` 采用 `nonce(12B)||ciphertext||tag` 自包含布局**。原表只说
   “AES-256-GCM(KEK, nonce=12B随机, master_key)”，但 `users` 表没有 wrapped_key 的 nonce 列，
   `pairs` 表与 `claim` 响应也没有 nonce 字段；不把 nonce 放进 blob 则领取方无法解密。
   条目密文不受影响（`items.nonce` 独立存储）。
3. **`POST /items` 增加 `deleted_at` 字段**。原接口要求 `GET /items` 返回墓碑（`deleted_at` 非空），
   但写入请求没有任何表达删除的字段。故增加可选 `deleted_at`（0/缺省=未删除）。
4. **`X-Vkey-Sig` 编码**原文未规定 → 定为 base64url 无填充的 64B 签名。
5. **`username_hint` 返回原文用户名**（不是掩码）：verifier 的 HKDF info 必须是精确的用户名，
   客户端需要它来计算 verifier。单用户自托管场景下不构成额外泄露。
6. **`devices/register` 只返回 `device_id`、不签发 token**（按原响应形状）。该端点只做公钥预登记；
   设备要获得 token 仍须走 `auth/token`（需要 verifier）。
7. **同一设备重新认证会作废旧 token**：`devices` 只有单 `token_hash` 列，无法多 token 并存。
8. **`/items` 的 `next` 在服务端回滚时可能小于 `since`**，客户端据此触发全量重拉。
9. **状态码细化**：配对码不存在=404、过期=410、已用/重复 code_id=409、密文超限=400、
   限流=429；原契约只写了部分。
10. **`--set-require-master-pw` 缺省不改策略**（不是重置为 false），避免重启意外放宽策略。
11. **`items` 主键由全局 `id` 改为复合主键 `(user_id, id)`**。原 schema 是
    `id TEXT PRIMARY KEY + UNIQUE(user_id, id)`，M1 单账号下成立；多用户（`user_mode=admin`）
    下不同账号写同名 item id 会触发全局 PK 冲突（500）。item id 由客户端自选，语义上只在
    账号内唯一。服务端打开旧库时按 SQLite 官方 12 步流程自动迁移（行数不变、幂等）；
     客户端协议字段不变，但所有依赖「id 全局唯一」的运维操作（如 `vkeyd purge` 的墓碑定位）
     必须按 `(user_id, id)` 成对处理。
12. **新增开户落地页 `GET /join?c=<CODE>` 与 `GET /join/qr.png?c=<CODE>`**（见 §4.13）。原契约
    开户码只能由客户端 API 直传；管理员 `vkeyd user add` 需一个可直接发给对方的链接，故新增
    两个免鉴权 HTML/QR 端点。开户码在 query 中属一次性凭据：契约要求访问日志对 `/join*` 脱敏
    （只记路径）、页面/日志不得出现 master_key/verifier/token、无效情形统一 4xx 文案防枚举、
    且落地页只读校验不消费开户码（消费仍仅在 `POST /api/v1/auth/enroll`）。
13. **新增 `GET /api/v1/update/android`**（见 §4.14）。原契约只有 `/dl/*` 静态分发 APK，没有
    「客户端从哪得知最新版本、该比哪个版本号、怎么校验完整性」的接口，客户端只能硬编码下载地址。
    裁定：新增免鉴权只读端点，服务端**只读 meta 表、不访问 GitHub API**（GitHub 与自托管两种
    分发方式共用同一响应形状），`version_code` + `sha256` 缺任一项即 204，客户端据此判断
    「暂无更新」。发布信息由运维 CLI 写入，故不引入新的写接口。

---

## 11. 兼容性纪律

- 新增响应字段必须可选、可忽略；已冻结字段不得改名/改类型/改语义。
- 新增请求字段必须可选，并明确默认值。
- 任何密码学常量、派生式、AAD、签名串的改动都是**破坏性变更**，必须同时更新
  `shared/vectors/*.json` 并把协议版本升到 0.2。
