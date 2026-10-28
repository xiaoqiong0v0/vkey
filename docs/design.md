# vkey — 自建 2FA + 虚拟安全密钥（方案草案 v0.1）

> 目标：一套自托管方案，同时提供 **Android 端 2FA(TOTP)** 与 **Linux / Windows 桌面端的 WebAuthn（虚拟 FIDO2 密钥）**，数据全部同步到自己的服务器。
> 本方案基于 2026-10-26 在 Fedora 44 / Chromium 156 上完成的可行性 spike（结论：**可行**，已实测通过 register + auth）。

---

## 1. 能力矩阵（第一版目标）

| 平台 / 形态 | TOTP 2FA | WebAuthn 凭据（passkey/安全密钥） | 说明 |
|---|---|---|---|
| Android (14+) | ✅ | ⏳ 第二阶段 | provider 需 ROM 支持 Credential Manager，国产 ROM 待实测 |
| Linux (Fedora/Ubuntu) | 备用 | ✅ 主路径 | `uhid` 虚拟 FIDO2 设备（spike 已验证） |
| Windows 11 24H2+ | 备用 | ✅ 主路径 | 官方 WebAuthn Plugin API（无需模拟 USB） |
| 任意浏览器（兜底） | — | ✅ 兜底 | 浏览器扩展劫持 `navigator.credentials` |
| 服务端 | — | — | 单二进制，零知识存储 |

**明确不做**：iOS（需 Apple 特批 entitlement）、手机当 USB 硬件密钥（Android 无公开 HID gadget API）、hybrid 扫码（中转在 Google 手里，国内不可用）、**H5/网页端（不在浏览器里解密或显示 TOTP/私钥）**。

---

## 2. 架构

```
                 ┌──────────────────────────────┐
                 │  vkeyd（服务端，单二进制）      │
                 │  · 账号/设备注册（单用户）      │
                 │  · 零知识密文条目存储           │
                 │  · 引导安装包/脚本分发          │
                 └───────────┬──────────────────┘
                             │ HTTPS（TLS，可自签或 LE）
      ┌──────────────┬───────┴────────┬────────────────┐
      │              │                │                │
┌─────┴─────┐  ┌─────┴─────┐   ┌──────┴──────┐  ┌──────┴──────┐
│ Linux     │  │ Windows   │   │ 浏览器扩展   │  │ Android     │
│ vkey-hid  │  │ vkey-win  │   │ vkey-ext    │  │ vkey-android│
│ (Rust)    │  │ (Rust/COM)│   │ (TS, MV3)   │  │ (Kotlin)    │
│ uhid+CTAP2│  │ Plugin API│   │ 页面劫持     │  │ TOTP(+provider)│
└───────────┘  └───────────┘   └─────────────┘  └─────────────┘
```

四个客户端**共用**同一份「密文条目格式 + 同步协议」，所以任何一端写入，其它端立即可用。

---

## 3. 对原始设想的修正（重要）

### 3.1 ❌「服务启动后动态生成 Android/Linux/Windows 安装文件」→ ✅「动态生成引导脚本 + 通用安装包」

动态产出各平台安装包代价极高、且不安全：

| 做法 | 代价 | 风险 |
|---|---|---|
| 服务端内构建 APK | 需 Android SDK（容器 ~10GB）+ 内置签名 keystore | keystore 放服务端 = 拿到服务器就能伪造你的 APK |
| 服务端内构建 deb/rpm/msi | 需交叉工具链 | 每次发布都要重跑，构建环境与运行环境耦合 |
| **引导脚本 + 通用产物** | 服务端只做字符串模板 | 无签名材料、无 SDK |

**推荐设计**：服务端只提供三个**参数化引导端点**，产物是「已经带好你的服务器地址」的安装入口：

```
GET /install.sh            # curl -fsSL https://<host>/install.sh | bash
GET /install.ps1           # irm https://<host>/install.ps1 | iex
GET /pair                 # 手机扫码页（返回一次性配对 token + APK 下载 + 服务器地址）
GET /dl/<artifact>         # 预构建产物：vkey-hid-linux-x86_64.tar.gz、vkey-win.msi、vkey-ext.zip、vkey-android.apk
```

脚本逻辑（两端一致）：探测架构 → 下载对应产物 → 写入 `~/.config/vkey/config.toml`（`server_url`、`device_id`、`token`）→ 注册为 systemd user / Windows 服务 → 打印一次配对确认。
**效果与「动态安装包」完全一致**（用户一条命令装好且已指向你的域名/IP），成本差两个数量级，还顺带解决「域名 or IP 可配置」。

### 3.2 ❌ Android 一上来就做 passkey provider → ✅ 第一版只做 TOTP + 查看/确认

`CredentialProviderService` 在 AOSP 14+ 存在，但国产 ROM（vivo/小米/华为）是否暴露入口、是否允许第三方 provider **未知且不可控**。因此：

- 第一版 Android：TOTP 列表 + 扫码添加 + 与服务器同步 + 「本次登录待确认」的审批页（用作桌面端的 UX 前置，不是硬依赖）
- 第二阶段：加 `CredentialProviderService`，并以「ROM 支持才启用」为特性开关

### 3.4 ❌ 不做 H5/网页端（2026-10-26 决策）

原因：端到端加密的前提是**私钥只在受信任的客户端解密**。一旦在浏览器里解密主密钥或显示验证码，安全就退化为「信任服务端下发的 JS」——服务端被入侵或供应链污染即可静默窃取主密码与明文，E2EE 形同虚设。附带问题：`localStorage` 中的 token 遇 XSS 直接被偷、DOM 里的 TOTP 明文可被任意扩展读取、`getUserMedia` 在国产浏览器/WebView 支持参差。

**服务端仍然保留的网页**（纯展示，不含任何解密逻辑）：

- `/pair` — 一次性配对码 + Android APK 下载 + 服务器地址
- `/install.sh` `/install.ps1` — 引导安装脚本
- `/` — 自检页（服务状态、已注册设备、同步条目数、TLS 有效期）

这三个页面**不接触**主密码、密文解密或验证码生成。


### 3.3 ✅ 保留浏览器扩展，但不是主路径

扩展的价值是覆盖「Windows 11 24H2 以下」和「Firefox/其它 Chromium」，以及作为虚拟密钥不可用时的兜底。安全边界需在 UI 明示（扩展 = 软件密钥，低于硬件密钥）。

---

## 4. 服务端设计

### 4.1 语言与形态
**Go 单二进制**（不选 Rust：交叉编译链路短、部署简单；不选 Node：无运行时依赖）。`sqlite` 默认、`postgres` 可选（环境变量切换）。

### 4.2 数据模型（零知识）

```
users(id, username, verifier, pw_salt, wrapped_key, created_at)
devices(id, user_id, name, platform, pubkey_ed25519, revoked_at, created_at, last_seen)
items(id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at)
  kind ∈ {totp, webauthn}
  ciphertext = AES-256-GCM(item_key, {...})
item_conflicts(id, user_id, item_id, ciphertext, nonce, version, updated_at)  -- LWW 落败副本
audit(id, user_id, device_id, action, ts)                    -- 仅元数据，不含明文
```

- **`master_key` 是账号级 32B 随机值**（2026-10-26 修正：原方案从主密码派生，无法支持「默认无密码 + 多设备共享」），**永不上传**
- `verifier = HKDF-SHA256(master_key, salt="vkey-verifier", info=username)` → 上传，仅用于登录校验
- **主密码是可选的包裹层**：启用时 `wrapped_key = AES-256-GCM(KEK, master_key)`，`KEK = Argon2id(pw, pw_salt, m=64MiB, t=3, p=1)`；`pw_salt`/`wrapped_key` 存服务端（服务端无法解），新设备凭密码取回 `master_key`
- **是否强制主密码 = 服务端策略**（`GET /api/v1/policy`，客户端每次启动必查；本地改配置不生效）。默认 `require_master_pw=false`
- 未启用主密码时，`master_key` 由设备本地密钥文件包裹存盘（`0600`）
- 条目加密：`item_key = HKDF-SHA256(master_key, salt="vkey-item", info=item_id)`；`AES-256-GCM`，12B 随机 nonce，AAD=`vkey-item|`+item_id
- 服务端只见密文；`rp_id` 明文保留用于检索/去重
- **冲突策略**：`version` 由服务端单调分配，LWW（last-write-wins），落败副本进 `item_conflicts`

### 4.3 API（最小集）

```
GET  /api/v1/policy                                           -> {require_master_pw, kdf:{m,t,p}, min_client_version}
POST /api/v1/auth/token        {username, verifier}           -> {token, device_id, pw_salt, wrapped_key}
GET  /api/v1/items?since=<ver>                                -> [{id, kind, rp_id, ct, nonce, version, updated_at}]
POST /api/v1/items             {items:[{id, kind, rp_id, ct, nonce, base_version, updated_at}]}
POST /api/v1/devices/register  {name, platform, pubkey}       -> {device_id}
POST /api/v1/pair/new          (需鉴权)                        -> {code_id, code, expires_at}
POST /api/v1/pair/claim        {code, name, platform, pubkey} -> {token, device_id, blob, pw_salt}
GET  /api/v1/health
```

鉴权：`Authorization: Bearer <device_token>` + `X-Vkey-Sig`（设备 Ed25519 对 `METHOD\nPATH\nsha256(body)\nts` 签名）+ `X-Vkey-Ts`（±120s），防 token 泄漏后直接拉库。

---

## 5. 各端实现要点

### 5.1 Linux（Rust + uhid）— spike 已验证
- 复用 spike 结论，**10 个坑必须内化**（见 §8）
- 架构：`vkey-hid`（systemd user service）→ `/dev/uhid` 虚拟设备 → 每次 CTAP2 请求时从**本地加密缓存**读私钥解密签名，签名后立即清零
- 权限：udev 规则给 `uinput`/`uhid`/`hidraw` 授权（`uaccess` 或固定 group），**避免要求 root 常驻**
- 已解决（2026-10-27）：`rk:true` 的阻塞实为 `GetInfo.options` 未声明 `rk`/`uv` 导致的 `kMissingCapability` 预检；声明 `{rk,up,uv}` 后 passkey 注册/登录均通过（UV = `up` 口径）

### 5.2 Windows（Rust + WebAuthn Plugin API）— 需验证
- Windows 11 24H2+ 官方 `webauthnplugin.h`：注册 COM `IPluginAuthenticator`，UV 走 Windows Hello（体验最好）
- Win10/11 老版本：退回浏览器扩展
- 需代码签名证书（否则 SmartScreen 拦截）；可先自签 + 文档说明

### 5.3 浏览器扩展（TypeScript, MV3）
- 页面主世界脚本劫持 `navigator.credentials.create/get`（Bitwarden 同法，已取证）
- 与本地 daemon 通信：`nativeMessaging`（扩展 ↔ `vkey-hid`/`vkey-win`）；没装 daemon 时直接走服务器（能力受限）
- 风险：站点隔离/CSP；需准备「复制一次性验证码」降级

### 5.4 Android（Kotlin + Compose）
- 第一版：TOTP（RFC 6238）、扫码导入、E2EE 同步、生物识别解锁
- 第二阶段：`CredentialProviderService`（API 34+），启动时探测 ROM 是否支持，不支持则隐藏该功能
- 第三阶段（可选）：蓝牙 HID 键盘自动输码（免谷歌、免插件）

---

## 6. 一站式交付（对应你的「自定义服务」诉求）

服务器启动后（首次 `vkeyd init --domain <域名|IP>` 或环境变量），自动生成：

1. `https://<host>/install.sh` / `install.ps1` — 带 `server_url` 的引导脚本
2. `https://<host>/pair` — 手机扫码页：一次性配对码 + APK 下载 + 指纹校验
3. `https://<host>/` — 自检页：显示服务状态、已注册设备、同步条目数、TLS 有效期
4. TLS：内置 ACME（Let's Encrypt）或 `--self-signed`（IP 场景，附 CA 导出说明）

「域名或 IP」两种模式都要支持：IP 模式走自签 CA + 引导脚本自动安装根证书（Windows 用 `certutil -addstore`，Linux 用 `update-ca-certificates`）。

---

## 7. 已知风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| `rk:true` + RP 要 residentKey → Chrome 静默等待超时（spike 实测） | 无法做无用户名 passkey | **已解决（2026-10-27）**：根因是 `GetInfo.options` 未声明 `rk`/`uv`，Chrome 在 `authenticatorSelection` 预检即判 `kMissingCapability`，`makeCredential` 从未发出。声明 `{rk:true, up:true, uv:true}` 后 V2/V3/V4 全通过；UV 口径 = `up` 即 uv（软件密钥，README 已注明） |
| RP 用 `allowCredentials[].transports` 限定传输（如 npm 只给 `["hybrid","internal"]`） | 虚拟 USB 密钥被**合法排除**，弹窗只给二维码、daemon 零 CTAP 流量 | **站点侧限制，非设备缺陷**。解法：先走该站「新增安全密钥/passkey」的 create 流程（通常不带 transports 限制），注册后新凭据带 `usb` transport，之后登录即可被枚举。npm 实测：注册 `0x01 ok` → 登录 `0x02 ok` |
| 虚拟密钥 = 软件密钥，本机恶意进程可调用 | 安全等级低于 YubiKey | UI 明示；私钥仅在签名瞬间解密；可选「每次确认」（polkit/Hello） |
| 国产 ROM 不暴露 Credential Manager | Android passkey 不可用 | 特性开关 + 文档；TOTP 不受影响 |
| 扩展劫持遇 CSP/站点隔离 | 个别站点不可用 | 降级到「一次性验证码复制」 |
| 主密码丢失 | 数据永久不可解 | 恢复码（BIP39 风格）+ 导出加密备份 |
| Windows 代码签名 | SmartScreen 拦截 | 先提供自签 + 校验哈希；有证书后补签 |

---

## 8. spike 已确认的 10 个 CTAP2 实现坑（实现时必须内化）

1. `uhid_output_req.rtype` 是 **HID 报表类型**（1=output），不是 0
2. 无 report ID 的设备，Chrome 写 **65 字节**（`0x00` + 64 字节帧），必须剥前缀
3. CBOR `true/false` = `0xF5/0xF4`（写成 `0x15/0x14` 变成整数 21/20）
4. `getInfo.versions` 必须是 **array**
5. **`clientPin:false` 表示「支持但未设 PIN」**，会强制要求 `pinUvAuthProtocols`；不打算支持 PIN 就**不要声明**
6. 每次 INIT 必须分配**唯一 CID**（Chrome 同时开多个 handle）
7. CTAP2.1 需实现 **`authenticatorSelection(0x0B)`**（Chrome 的 GetTouch），否则停在「插入并轻触」
8. 声明 **`rk:true`** 且 RP 请求 residentKey → Chrome 静默超时
9. ES256 签名必须是 **DER**（不是 raw r‖s）
10. CTAP2 错误应答只能是**单个状态字节**
11. **getAssertion 应答外层键位是 `1=credential / 2=authData / 3=signature / 5=numberOfCredentials`**（不是 1=authData），且 descriptor 与 user 实体**内层用文本键**：`{"type":"public-key","id":<bytes>}`、`{"id":<bytes>}`。依据 Chrome 156 `public_key_credential_descriptor.cc`（`kCredentialIdKey="id"`、`kCredentialTypeKey="type"`）与 `device_response_converter.cc:242-274`；键位或内层写错 → Chrome 合成 `kCtap2ErrInvalidCBOR(0x12)` 且 JS Promise 永不 settle
12. **不做 UV 且非 discoverable 时，getAssertion 不得返回 user 实体（0x04）**，否则 `get_assertion_request_handler.cc:138-143` 判非法，回 `NotAllowedError`
13. **CTAPHID 响应首字节必须是状态码**（成功 = `0x00` + 裸 CBOR；错误 = 单字节状态码）。去掉成功响应的 `0x00` 会让 Chrome 把 CBOR 首字节当状态码读（实测 `GetInfo` 报 error 166 = `0xA6` = map(6) 头），整条链路 0/4 全挂
14. **passkey 站点要求 `rk`+`uv` 能力**：`GetInfo.options` 缺任一项，Chrome 在发命令前就判 `kMissingCapability`（表现为弹窗只给二维码/一直等插入），加 `--vmodule=device/fido/*=3` 可看到 `authenticator_request_dialog_model.cc` 的 UI step

### 8.1 服务端与运维踩坑（2026-10 实测）

1. **墓碑写入会不可逆销毁密文**：客户端推 `deleted_at != 0` 的墓碑时，服务端把 `ciphertext`/`nonce` 一并清空（协议允许空串）。
   实测事故：旧版 Android 把本地标记删除的 webauthn 条目批量推成墓碑，**抹掉了 Fedora 侧 21 条 passkey**，只能从备份恢复。
   → 纪律：客户端**不得把非本机创建的条目推成墓碑**；服务端若要支持事后恢复，墓碑应保留密文（当前实现仍会清空，恢复依赖备份）。
2. **`cp vkeyd.db` 不等于备份**：SQLite 的 WAL 里可能还有未 checkpoint 的最新写入，只拷主文件会得到「旧状态」。
   实测：`cp` 出来的两份备份 sha256 完全相同，而它们的产生时间差了 1 小时。
   → 一律用 `server/deploy/backup.sh`（SQLite backup API，天然含 WAL）。
3. **恢复数据后必须同步 `meta.seq`**：直接改 `items.version` 而不同步 `meta['seq:<user_id>']`，会让 `GET /items` 的 `next` 停在旧值，客户端每轮都会把同一页再拉一遍（实测 `total=42 ok=21`）。
4. **访问日志已脱敏**：`journalctl -u vkeyd` 只有 `METHOD path -> status (ms)`，无 token / 无 body / 无签名；22 条关键词命中全是外部扫描器探测（`/.aws/credentials`、`/user_secrets.yml` → 404）与路由名本身。
   → 该结论有实测支撑，但**新增日志时必须复查**，别把 `X-Vkey-Sig` 或 body 打进日志。
5. **备份加密用 GPG 非对称**：服务器只留公钥（`secret=0 public=1`），私钥只在运维方本机；加密需 `--trust-model always`（公钥无信任网）。
   备份产物 `data/backups/vkeyd-<ts>.db.gpg`，cron 每日 04:17，保留 30 天，加密前做 `integrity_check` + 条数自检。

---

## 9. 里程碑

| 阶段 | 内容 | 验收 |
|---|---|---|
| M0 ✅ | Linux uhid 虚拟密钥 spike | Chromium register+auth 成功（已完成） |
| M1 ✅ | 服务端 vkeyd（账号/同步/配对/主密码包裹/引导脚本）+ Linux daemon（uhid + CTAP2 + 同步） | 两台 Linux 共享同一份 passkey：Fedora 真机 Chromium register 231ms / auth 15ms 通过；第二设备 `pair` 领取后 `sync` 解密成功 |
| M2 | 浏览器扩展（兜底）+ Windows Plugin API PoC | Win11 下 Chrome 可直接用 |
| M3 | **Android 第一版 = TOTP 管理器**（`minSdk 26`、强制恢复码、TOTP 外层 `rp_id="totp"`、新增 `GET /api/v1/devices` 设备列表）；详细方案见 **`docs/android.md`** | 手机加码桌面可见 |
| M4 | 打包交付：install.sh / install.ps1 / pair 页 / TLS | 新机器一条命令接入 |
| M5（可选） | Android CredentialProviderService、蓝牙 HID 输码 | ROM 支持时启用 |

---

## 10. 目录结构（本仓）

```
vkey/
├── docs/                # 本方案、CTAP2 笔记、证据
├── server/              # Go 单二进制（vkeyd）
├── linux/               # Rust daemon（uhid + CTAP2）
├── windows/             # Rust/C++ Plugin API 实现
├── extension/           # TypeScript MV3 扩展
├── android/             # Kotlin app
├── shared/              # 协议/密文格式定义（JSON schema + 测试向量）
└── spike/               # 已完成的可行性验证（保留为参考实现 + 回归测试）
```

---

## 11. 已定决策（2026-10-26）

| 项 | 决定 |
|---|---|
| 项目名 | `vkey` |
| 服务端语言 | **Go 单二进制**（纯 Go sqlite 驱动 `modernc.org/sqlite`，便于交叉编译） |
| 第一版范围 | **服务端 vkeyd + Linux daemon**（M1）；Windows/Android 依次跟进 |
| 代码布局 | 根下并列子目录 `server/ linux/ windows/ extension/ android/ shared/`，`docs/ spike/` 原位 |
| 主密钥模型 | 32B 随机 `master_key`（见 §4.2），主密码为可选包裹层 |
| 主密码策略 | 服务端下发，**默认不要求** |
| 部署目标 | `ecs-user@47.97.78.223:~/work/vkey/`，nginx 反代 + certbot，域名 `vkey.xiaoqiong0v0.cn` |
| 机器 B 验收 | Fedora 上 podman 容器（`--device /dev/uhid`）跑完整 Chrome；Kali WSL 做同步/解密交叉验证（WSL2 内核 `CONFIG_UHID=n`，无法跑 HID 全链路） |
| 工具链 | Go 1.27.3（mise，项目 `mise.toml` 钉版）；Rust 在 Fedora 原生构建 |
