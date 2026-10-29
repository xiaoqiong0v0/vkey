# vkey Android 客户端方案（第一版：TOTP 管理器）

- 状态：**定稿 v1.0（2026-10-27 拍板转正）**；实施按 §10 里程碑推进，决策见 §12
- 日期：2026-10-27
- 范围：`docs/design.md` 的 **M3**，且按已冻结口径**只做 TOTP**：列表 / 添加 / 同步 / 生物识别解锁
- 明确不做：`CredentialProviderService`、passkey、H5/网页端解密、iOS、蓝牙 HID 输码
- 契约唯一来源：`shared/protocol.md`（下称「协议」）+ `shared/vectors/*.json`
- 本文所有「协议」引用均为 `shared/protocol.md:<行号>`；「设计」引用为 `docs/design.md:<行号>`

> 本文与 `docs/design.md` M3 配套；协议以 `shared/protocol.md` 为准

**目录**：[0 一页结论](#0-一页结论) · [1 技术选型](#1-技术选型) · [2 密码学落地](#2-密码学落地) · [3 数据层](#3-数据层) · [4 同步引擎](#4-同步引擎) · [5 配对与引导](#5-配对与引导) · [6 TOTP 实现](#6-totp-实现) · [7 UI 结构](#7-ui-结构) · [8 安全清单](#8-安全清单) · [9 构建与分发](#9-构建与分发) · [10 里程碑与验收](#10-里程碑拆分与验收) · [11 风险清单](#11-风险清单逐条缓解) · [12 决策状态](#12-决策状态)
> 附录：A 关键依据 · B 版本清单 · C 拍板记录

> 本地环境说明：本机**没有 Android SDK / JDK**（`ANDROID_HOME` 未设置、无 `java`），因此
> API level 结论来自官方文档原文（见附录 A），库的存在性通过**直接解包 Maven 产物**核对
> （`bcprov-jdk18on-1.86.jar` 已落 `.tmp/scratch/jars/`）。任何需要真机/模拟器的结论都标为「待验证」。

---

## 0. 一页结论

| 项 | 结论 |
|---|---|
| 技术栈 | Kotlin + Jetpack Compose（Material 3）+ 协程/Flow + Room + OkHttp + kotlinx.serialization |
| SDK | **minSdk 26 / targetSdk 36 / compileSdk 36**（理由见 §1.2） |
| 打包 | **自建 `/dl/vkey-android.apk` 优先**；Play 上架差异见 §9.4 |
| 密码学 | **JCA（AES-GCM / SHA-256 / HMAC）+ BouncyCastle lightweight（Ed25519 / Argon2id / HKDF）+ 自写 Base32**；**不用** Android Keystore 存 Ed25519（不支持） |
| 本地密钥保护 | Keystore AES-256-GCM 包裹「vault blob」+ `BiometricPrompt`（API 30+ 认证绑定密钥；26–29 降级策略见 §2.3） |
| 数据层 | Room 只存**密文 + 同步元数据**，不存明文 label/secret；解锁后内存解密 |
| 同步 | 单飞 `SyncEngine` + WorkManager 唯一任务；LWW 复用服务端语义，客户端只补「秒级时间戳单调化」 |
| 设备管理 | 列表 `GET /api/v1/devices`（签名、只读，协议增量见 §4.7）+ 吊销（协议 §4.9） |
| 里程碑 | **3 个**（M3.1 本地可用 / M3.2 同步与配对 / M3.3 生物识别与打磨） |
| 最大风险 | ① Keystore 密钥失效（刷机/移除锁屏/生物识别变更）导致 `master_key` 永久丢失；② 无推送、后台同步受国产 ROM/Doze 限制，同步延迟不可控 |

---

## 1. 技术选型

### 1.1 语言、UI、架构

| 层 | 选择 | 说明 |
|---|---|---|
| 语言 | Kotlin 2.4.21（稳定线；KSP 见 §1.3 备注） | 全量类型标注；协程 + `Flow` |
| UI | Jetpack Compose（Compose BOM `2026.09.00`）+ Material 3 | 单 Activity + Navigation Compose |
| 架构 | 单 Activity + 多模块；MVVM + 单向数据流（`StateFlow<UiState>`） | 分层：`ui → domain → data`，`core:crypto` 无 Android 依赖 |
| 异步 | `kotlinx-coroutines` 1.11.0；`SupervisorJob` + `Dispatchers.IO` 做 CPU/IO 隔离 | 见 §4.5 并发契约 |
| JSON | `kotlinx-serialization-json` 1.12.0 | 条目明文用 `JsonObject` 保留未知字段（协议 §5 要求） |
| HTTP | OkHttp 5.5.1 | 需要**精确控制** body 字节与 RequestURI（签名串，协议 §3.1） |
| DB | Room 2.8.5（KSP） | 不启用 SQLCipher（见 §3.1 取舍） |
| 依赖注入 | 手写 `AppContainer`（v1 不引入 Hilt） | 减少编译期魔法；后续可替换 |

**为什么不用 Hilt / 不用 SQLCipher / 不用 Tink：**

- Hilt：v1 模块数与依赖图很小，手写容器可读性更好，也避免与 AGP 9 的 KSP 组合踩版本坑。
- SQLCipher：条目本身已是 `AES-256-GCM` 密文，DB 里唯一敏感的是「条目数量、版本、时间」这类元数据；引入 SQLCipher 需要额外的 DB 口令保护与 16 KB 原生库对齐，收益小于成本。若后续要防「拿到 DB 文件看元数据」，再作为可选开关（§3.1 末尾）。
- Tink：Ed25519 在 Tink 里是 **keyset** 抽象，而协议要求「32B 原始种子 / 32B 原始公钥 / 64B 原始签名」（协议 §1 补充表）。用 BouncyCastle lightweight 可以直接对齐字节，少一层转换。

### 1.2 SDK 版本：minSdk 26 / targetSdk 36 / compileSdk 36

**建议：`minSdk = 26`（Android 8.0）、`targetSdk = 36`、`compileSdk = 36`、JDK 17。**
**已定（2026-10-27 拍板）：`minSdk = 26` 定稿**，不再保留「提到 30 简化分支」的可选项（见 §12.1）。

理由（设备兼容 vs 现代 crypto API）：

| 约束 | 数值 | 对 minSdk 的影响 |
|---|---|---|
| WorkManager 2.12.0 | minSdk **24**（2.11 还是 23） | ≥24 |
| androidx.biometric 1.1.0（稳定线） | minSdk **21**；1.4.0-alpha 起改 **23** | ≥23 |
| CameraX 1.6.2 / Compose / ZXing core | minSdk 21 / 21 / 纯 Java | ≥21 |
| `KeyGenParameterSpec.setInvalidatedByBiometricEnrollment` | **API 24** | ≥24 |
| `setIsStrongBoxBacked` / `setUnlockedDeviceRequired` | **API 28**（运行时判空降级） | 不强制 |
| `setUserAuthenticationParameters`（认证绑定密钥的现代写法） | **API 30**（26–29 有等价降级） | 不强制 |
| `java.time`（TOTP 里大量用 `Instant`） | API 26 原生 | 26 可免 desugaring 争议 |
| `ClipDescription.EXTRA_IS_SENSITIVE` | API 33（运行时判空） | 不强制 |

**为什么是 26，而不是 23/24 或 30：**

- 26 = Android 8.0，已经覆盖从 8.0 起的设备（具体占比取决于目标用户，不做「绝大多数」的断言），同时避开 Android 7.x 时代 Keystore 在部分厂商 ROM 上的历史缺陷（key blob 损坏、GCM 授权行为不一致）。
- 26 让 `java.time`、`KeyGenParameterSpec` 认证参数、`Cipher AES/GCM` 都处在成熟区间，代码里只需要为 **28/30/33** 三个特性做运行时分支，而不是到处 `Build.VERSION` 补丁。
- 不选 30：会把 Android 8–10 设备排除在外，而 30 独有的只有 `setUserAuthenticationParameters`，它在 26–29 有官方等价写法（`setUserAuthenticationValidityDurationSeconds(-1)`，见 §2.3）。
- 若要面向自己的新机型，理论上可把 `minSdk` 提到 **30** 来简化分支；**本方案已定为 26，不采用该简化**（§12.1）。

**targetSdk 36 的依据：** Google Play 自 **2026-08-31** 起要求新应用/更新 target **Android 16（API 36）**（附录 A-9）。自建分发不受 Play 强制，但：
- 行为一致（edge-to-edge、前台服务限制、后台启动限制）更容易只维护一套；
- 16 KB 页面支持（targetSdk 35+，2027-02-01 起强制）必须提前处理（附录 A-8）。

**targetSdk 36 的落地注意：**
- edge-to-edge 强制：`enableEdgeToEdge()` + `WindowInsets`，不要再用 `statusBarColor`。
- 前台服务：v1 不需要前台服务；同步走 WorkManager。
- 预测性返回：`android:enableOnBackInvokedCallback="true"`，Compose Navigation 自动处理。

### 1.3 依赖清单（2026-10-27 从 Maven 元数据核对）

| 依赖 | 版本 | 用途 |
|---|---|---|
| AGP | **9.4.1** | 构建；若与 KSP/Room 组合出问题，退回 8.x LTS 线（见 §12.2 第 8 项） |
| Kotlin | **2.4.21** | 语言 |
| KSP | **2.3.12**（KSP2 独立版本线） | Room 注解处理 |
| Compose BOM | **2026.09.00** | UI |
| Navigation Compose | 2.10.2 | 路由 |
| Lifecycle | 2.11.0 | `collectAsStateWithLifecycle` |
| Room | **2.8.5** | DB |
| WorkManager | **2.12.0** | 后台同步（注意 minSdk 24） |
| androidx.biometric | **1.1.0**（稳定） | 生物识别；1.4.0-alpha07 需 minSdk 23，可作为兼容性备选 |
| CameraX | **1.6.2** | 扫码预览/分析 |
| ZXing core | **3.5.4** | 二维码解码（离线、无 GMS） |
| OkHttp | **5.5.1** | HTTP + 签名拦截器 |
| kotlinx-serialization-json | **1.12.0** | JSON |
| kotlinx-coroutines | **1.11.0** | 并发 |
| BouncyCastle | **bcprov-jdk18on 1.86** | Ed25519 / Argon2id / HKDF（只用 lightweight API） |
| DataStore Preferences | 1.3.0 | 非敏感配置（server_url / last_since / clock_offset / wrapped_key 缓存） |
| JUnit5 / Robolectric / Truth | 最新稳定 | `core:crypto` 纯 JVM 测试 |

> 版本组合（AGP 9.4.1 × Kotlin 2.4.21 × KSP 2.3.12 × Room 2.8.5）**未在本机验证**（无 JDK/SDK），
> 列为 M3.1 的第一个门禁：`./gradlew :app:assembleDebug` 必须一次通过；不通过就按 §12.2 第 8 项的降级组合处理。

### 1.4 分发策略

| 方式 | 结论 | 说明 |
|---|---|---|
| **自建 `/dl/vkey-android.apk`** | **首选** | 与协议 §4.12 的产物白名单一致；服务器只做静态分发，签名私钥**永不进服务端**（设计 §3.1） |
| Play 上架 | 可选后续 | 需要 AAB、Play App Signing、Data safety、targetSdk 合规；见 §9.4 |

自建分发的代价是「未知来源安装 + Play Protect 提示 + 更新靠手动」，换来的是：无 Google 依赖、无商店审核、可完全离线内网部署。第一版明确选自建。

---

## 2. 密码学落地

### 2.1 算法 → 实现矩阵（含 minSdk 与坑）

| 需求 | 实现 | API/版本 | 已知坑 / 结论 |
|---|---|---|---|
| AES-256-GCM | JCA `Cipher.getInstance("AES/GCM/NoPadding")` + `GCMParameterSpec(128, nonce12)` | API 19+（我们 26+ 无分支） | 输出为 `ciphertext||tag`（16B tag 在尾部），与协议 §1「含 tag」一致；**nonce 绝不复用**；`doFinal` 的返回值整体即 `ct` |
| HKDF-SHA256 | BouncyCastle `HKDFBytesGenerator` + `HKDFParameters(ikm, salt, info)`；或 20 行 `Mac` 自实现 | 全版本 | **Android 没有公开的 `javax.crypto.KDF`/HKDF**（官方页 404，附录 A-7）→ 必须自带；`salt`/`info` 是原始 UTF-8 字节，不做截断/补零（协议 §1 补充表） |
| Ed25519 | BouncyCastle lightweight：`Ed25519PrivateKeyParameters(seed,0)` / `Ed25519PublicKeyParameters` / `Ed25519Signer` | 全版本（纯 Java） | JCA 的 `Signature("Ed25519")` 自 **API 33** 才有（附录 A-2），且 `KeyPairGenerator`/`KeyFactory` 官方表**未列** Ed25519（附录 A-1）；**Android Keystore 不支持 Ed25519**（附录 A-3）→ 设备私钥只能是软件密钥，用 Keystore 的 AES 密钥包裹 |
| Argon2id | BouncyCastle `Argon2BytesGenerator` + `Argon2Parameters.Builder(ARGON2_id)` | 全版本（纯 Java） | 参数必须取 `/policy.kdf`（m/t/p），不能写死；**并对下发值做上界校验**（m ≤ 256 MiB、t ≤ 10、p ≤ 4），防止恶意/错误配置打爆内存；64 MiB 纯 Java 在低端机上可能 3–8 s，需实测（§11 风险 7）；native 方案（Signal argon2 13.1）会引入 ABI/16 KB 对齐问题 |
| Base32 | 自写 RFC 4648（大写、无填充；解码容忍小写/`-`/空格/`=`） | 全版本 | Java/Android **没有内置 Base32**；也可用 `commons-codec`，但自写 40 行更容易保证「严格编码 + 宽容解码」（协议 §1.2/§1.3） |
| SHA-256 / HMAC-SHA256 | `MessageDigest` / `Mac` | 全版本 | 签名串里 `hex` 必须**小写**（协议 §3.1） |
| 安全随机 | `java.security.SecureRandom` | 全版本 | `master_key`(32B)、配对码(32B)、token(32B)、GCM nonce(12B)；不要用 `Random`/`kotlin.random` |
| 生物识别 | `androidx.biometric.BiometricPrompt` + Keystore 认证绑定密钥 | 库 21+；`setAllowedAuthenticators` 1.1.0+ | **`BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` 在 API 28–29 调 `build()` 会报错**；`DEVICE_CREDENTIAL` 单独使用在 API 30 以下不支持（附录 A-4） |
| Keystore 包裹密钥 | `KeyGenerator(AES, "AndroidKeyStore")` + `KeyGenParameterSpec` | API 23+ | StrongBox 28+（可能 `StrongBoxUnavailableException`）；`setUserAuthenticationParameters` 30+；`setUnlockedDeviceRequired` 28+ |

**BouncyCastle 在 Android 上的注意事项（必须内化）：**

1. 只依赖 `org.bouncycastle:bcprov-jdk18on:1.86`，**只调用 `org.bouncycastle.crypto.*` lightweight API**。
2. **不要** `Security.addProvider(BouncyCastleProvider())`：Android 自带裁剪版 BC（不同包名/不同实现），注册会改变全局 JCA 行为，导致 `Cipher`/`Signature` 解析到非预期实现。
3. 不要用 BC 的 JCA 包装类（`org.bouncycastle.jce.*`），避免与系统 provider 冲突。
4. R8：lightweight API 是直接引用，通常无需额外 keep；若 release 出现 `ClassNotFoundException`，再加最小 keep（`-keep class org.bouncycastle.crypto.** { *; }` 只作为兜底，不要默认开）。
5. `bcprov-jdk18on` 是 Java 8 字节码，minSdk 26 直接用；不需要额外 desugaring 配置。

已本地核对的类（解包 `bcprov-jdk18on-1.86.jar`）：

```
org/bouncycastle/crypto/generators/Argon2BytesGenerator.class
org/bouncycastle/crypto/params/Argon2Parameters.class (+ Builder)
org/bouncycastle/crypto/generators/HKDFBytesGenerator.class
org/bouncycastle/crypto/params/HKDFParameters.class
org/bouncycastle/crypto/params/Ed25519PrivateKeyParameters.class
org/bouncycastle/crypto/params/Ed25519PublicKeyParameters.class
org/bouncycastle/crypto/signers/Ed25519Signer.class
```

**Argon2 的两个易错点：**
1. 必须显式 `.withVersion(Argon2Parameters.ARGON2_VERSION_13)`（v=0x13），否则与 RFC 9106/Go 实现对不上；
2. BC 的 `withMemoryAsKB(m)` 单位是 **KiB**，服务端 `/policy.kdf.m` 是 `65536`（KiB），不要误当字节或 MiB。

### 2.2 与「已冻结前提」的冲突与落地替代（2026-10-27 已全部拍板，见 §12）

> 以下是 Android 现实与现有表述不一致的点；**不是要改协议**，而是要在实现里明确替代方案。全部结论已于 2026-10-27 拍板，本文正文即最终口径（§12.1 汇总）。

**冲突 1：Ed25519 私钥不能放进 Android Keystore。**
- 依据：`KeyProperties` 没有 `KEY_ALGORITHM_ED25519` 常量，Keystore 支持的 `KeyPairGenerator` 算法只有 EC/RSA（附录 A-3）；StrongBox 支持集也只有 RSA/AES/ECDSA-ECDH P-256/HMAC-SHA256。
- 替代：设备身份 = **32B Ed25519 种子**（`SecureRandom` 生成）→ 用 Keystore 的 AES-256-GCM 密钥包裹后落盘；签名时临时解包到内存，签完清零。**安全等级低于硬件绑定私钥**，在设置页明示。
- 协议侧不受影响：公钥仍是 32B、签名仍是 64B（协议 §1 补充表）。

**冲突 2：「生物识别解锁」在 API 26–29 无法用「设备凭据 + 每次认证」的认证绑定密钥。**
- 依据：`BIOMETRIC_STRONG | DEVICE_CREDENTIAL` 组合在 API 28–29 `PromptInfo.build()` 直接抛错（附录 A-4）。
- 替代（分支策略，见 §2.3）：
  - API 30+：`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`（每次使用都要认证，生物识别或锁屏密码均可）。
  - API 26–29：有强生物识别 → `setUserAuthenticationValidityDurationSeconds(-1)`（每次都要生物识别）；无生物识别 → 正数有效期 + `KeyguardManager` 确认设备凭据（**明确较弱**，设置页标注）。

**冲突 3（产品级，最重要）：默认无主密码时，`master_key` 的唯一副本由 Keystore 保护；Keystore 密钥一旦失效，数据永久不可解。**
- 依据：认证绑定密钥在「移除安全锁屏 / 生物识别变更（默认）/ 恢复出厂」后会被永久失效（`KeyPermanentlyInvalidatedException`）。
- 影响：默认策略 `require_master_pw=false`（设计 §4.2）意味着没有服务端 `wrapped_key` 兜底。
- **强制增量（已定 2026-10-27）**：首次引导必须让用户保存 **`master_key` 的 base32（52 字符）恢复码**，并完成「抄写 + 回填校验」；未通过校验不得进入主界面（实现细节见 §5.5）。恢复码是 Keystore 失效后的唯一生路（Room 里的密文仍可用 mk 解开）。
- 可选增量：M3.3 支持设置主密码（`POST /auth/password`），给自己留第二把钥匙。

**冲突 4：`rp_id` 对 TOTP 没有定义。**
- 依据：协议 §4.6 要求 `rp_id` 1..255 字节且创建后不可变；服务端校验见 `server/internal/api/items.go:124`。但 `shared/examples/item-totp.json` 没有 `rp_id`，`kind=totp` 也没有语义。
- **已定（2026-10-27）**：**TOTP 条目的外层 `rp_id` 固定为常量 `"totp"`**（不泄露 issuer；不可变也天然满足）。Android 按此实现，Linux 端使用同一常量；数据层与协议映射的完整说明见 §3.6，常量本身需同批补进 `shared/protocol.md`。
- 注意：`rp_id` 只影响服务端去重/检索，不影响解密；但两端取值不一致会让后写入方被判 `status=rejected, reason=rp_id_mismatch`（协议 §4.6），因此必须同值。

**冲突 5：协议没有「设备列表」接口。**
- 依据：协议 §4 只有 `devices/register`（§4.8）与 `devices/revoke`（§4.9），**没有 `GET /devices`**。
- 影响：设置页只能显示「本机」，无法列出并吊销其它设备（吊销需要 `device_id`）。
- **已定（2026-10-27）**：**新增 `GET /api/v1/devices`**（签名、只读），设置页据此列出本账号设备并按协议 §4.9 吊销任一设备（含本机）。接口契约见 §4.7；该接口是协议增量，需同批补进 `shared/protocol.md` 与服务端实现，落地前设置页降级为「仅显示本机」。

### 2.3 密钥层次与本地保护

```
用户可见：
  恢复码 (base32 52 chars)  ── 手动输入/保存 ──┐
  主密码（可选，服务端策略） ── Argon2id ──┐    │
                                          ▼    ▼
                                      master_key (32B, 仅内存)
                                          │
        ┌─────────────────────────────────┼──────────────────────────┐
        ▼                                 ▼                          ▼
  verifier (上传)                  item_key = HKDF(mk,"vkey-item",id)   Ed25519 种子 (32B)
        │                                 │                          │
        ▼                                 ▼                          ▼
  POST /auth/token                 AES-256-GCM(条目明文)          Ed25519 签名（请求头）

本地落盘（全部在 noBackupFilesDir / DataStore）：
  vault.bin   = AES-256-GCM(KeystoreKey, nonce||CBOR{ ed25519_seed, token, device_id,
                                                      username, mk? })
  prefs       = server_url, last_since, clock_offset, policy_cache,
                pw_salt, wrapped_key（后两者是服务端下发的密文，非明文密钥）
```

**两种解锁模式：**

| 模式 | 触发条件 | 冷启动怎么拿 `mk` | 生物识别角色 |
|---|---|---|---|
| A. 无主密码（默认） | `require_master_pw_enforced=false` | Keystore 解包 `vault.bin` 里的 `mk` | `BiometricPrompt(CryptoObject)` 授权 Keystore 密钥；认证通过才能解包 |
| B. 强制主密码 | `require_master_pw_enforced=true` | 用户输入主密码 → `Argon2id` → 解 `wrapped_key` 得 `mk`；**不得**回退到 Keystore 里的副本（协议 §4.1） | 仅作为**同一会话内**的再解锁（mk 已在内存，或 5 分钟内短缓存）；冷启动必须密码 |

**`require_master_pw=true` 但 `require_master_pw_enforced=false`**：按协议 §4.1，客户端**必须报错**并提示先在已登录设备执行 `vkey-hid passwd`，不得静默回退。UI 文案见 §7。

**Keystore 密钥生成（伪代码，≤30 行）：**

```kotlin
private fun createWrappingKey(alias: String) {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val spec = KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)
        .setInvalidatedByBiometricEnrollment(false)   // 取舍见下
        .apply {
            if (Build.VERSION.SDK_INT >= 30) {
                setUserAuthenticationParameters(
                    0, // 0 = 每次使用都要认证
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(-1) // 仅生物识别，每次
            }
            if (Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) // 失败则 catch 重试
        }
        .build()
    kg.init(spec)
    kg.generateKey()
}
```

**`setInvalidatedByBiometricEnrollment(false)` 的取舍（必须写进设置页）：**
- 该标志只对「要求认证且**没有正数有效期**」的密钥生效（即每次认证/生物识别门控）；带正数有效期的弱模式里它会被忽略（附录 A-16）。混合了 `AUTH_DEVICE_CREDENTIAL` 时的实际行为以真机实测为准。
- `true`（系统默认）：新增/删除指纹会让密钥永久失效 → 恢复码成为唯一出路；安全性更高。
- `false`（本方案默认）：新增指纹不会毁掉密钥；代价是「知道锁屏密码的人可以录入自己的指纹再解锁」。
- 建议：默认 `false` + 强制恢复码；高级设置里提供「生物识别变更后使密钥失效（更安全，需恢复码）」开关。

**为什么不用 `EncryptedSharedPreferences`：** 它底层同样是「Keystore 密钥 + 文件加密」，但会多引入一层库依赖和它自己的版本/弃用节奏；本方案只需要一个自包含的 `vault.bin`（nonce||ciphertext），自写更可控，也便于把「哪些字段在 vault 里、哪些在明处」写清楚。

**降级路径（必须实现）：**
1. `StrongBoxUnavailableException` → 去掉 `setIsStrongBoxBacked` 重试。
2. API 26–29 且无强生物识别 → 走「设备凭据 + 正数有效期」的弱模式，设置页标注「本机无强生物识别」。
3. `KeyPermanentlyInvalidatedException` / `UserNotAuthenticatedException`：
   - 若是「刚认证完仍失败」→ 提示重试；
   - 若是密钥失效 → 进入**恢复流程**：输入恢复码（或重新配对）→ 重建 Keystore 密钥与 vault；
   - Room 里的条目密文**不删**，用新 mk 校验能否解密（能解则数据没丢）。

### 2.4 关键接口签名（不放完整实现）

```kotlin
// core:crypto —— 纯 Kotlin/JVM，无 Android 依赖；所有函数都是字节级契约
object VkeyCrypto {
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int = 32): ByteArray
    fun verifier(masterKey: ByteArray, username: String): ByteArray
    fun itemKey(masterKey: ByteArray, itemId: String): ByteArray
    fun itemAad(itemId: String): ByteArray                    // "vkey-item|" + id

    fun sealItem(key: ByteArray, plaintext: ByteArray, itemId: String): SealedItem  // nonce 随机
    fun openItem(key: ByteArray, nonce: ByteArray, ct: ByteArray, itemId: String): ByteArray

    fun sealSelfContained(kek: ByteArray, plaintext: ByteArray): ByteArray  // nonce||ct||tag，无 AAD
    fun openSelfContained(kek: ByteArray, blob: ByteArray): ByteArray

    fun argon2id(pw: ByteArray, salt: ByteArray, mKiB: Int, t: Int, p: Int, len: Int = 32): ByteArray
    fun pairKek(code: ByteArray, codeId: String): ByteArray   // salt="vkey-pair", info=code_id

    fun ed25519FromSeed(seed: ByteArray): Ed25519Key          // seed 32B
    fun ed25519Sign(key: Ed25519Key, message: ByteArray): ByteArray
    fun ed25519PublicRaw(key: Ed25519Key): ByteArray          // 32B

    fun b32Encode(bytes: ByteArray): String                   // 大写、无填充
    fun b32DecodeTolerant(text: String): ByteArray            // 容忍小写/-/空格/=
}
```

```kotlin
// core:network —— 协议 §3/§4 的最小面
interface VkeyApi {
    suspend fun policy(): PolicyDto
    suspend fun health(): HealthDto                    // 只为读 Date 头校时
    suspend fun authToken(body: AuthTokenRequest): AuthTokenResponse
    suspend fun pushItems(items: List<ItemUpload>): PushResponse
    suspend fun itemsSince(since: Long): ItemsPage
    suspend fun pairClaim(body: PairClaimRequest): PairClaimResponse
    suspend fun devices(): DevicesResponse              // GET /devices，只读（§4.7）
    suspend fun revokeDevice(deviceId: String): OkDto
    // devices/register 在 v1 不需要：claim 会创建设备；重装后走 auth/token upsert
}
```

**`master_key` 内存持有：**

```kotlin
class MasterKeyHolder {
    private val mutex = Mutex()
    private var mk: ByteArray? = null

    suspend fun <T> withKey(block: (ByteArray) -> T): T = mutex.withLock {
        val key = requireNotNull(mk) { "locked" }
        block(key)
    }

    fun unlock(key: ByteArray) { mk?.fill(0); mk = key.copyOf() }
    fun lock() { mk?.fill(0); mk = null }
}
```

> 说明：Kotlin/JVM 无法保证所有副本都被清零（GC、`String`、日志、异常栈）。这里的清零只覆盖我们持有的 `ByteArray`，是「降低暴露窗口」而非强保证；文档不要写成「内存绝对安全」。

### 2.5 与 `shared/vectors` 的一致性测试

**分层：**

| 层 | 位置 | 内容 | 运行环境 |
|---|---|---|---|
| 纯 JVM 单测 | `core/crypto/src/test` | `kdf.json` / `aead.json` / `signing.json` / `encoding.json` 全量逐字节比对；RFC 6238 官方向量 | 无需模拟器，毫秒级 |
| 仪器测试 | `app/src/androidTest` | Keystore 生成/包裹/生物识别门控、Room 迁移、`FLAG_SECURE` | 模拟器/真机 |

**向量文件同步（防漂移）：**

- Gradle 任务 `syncSharedVectors`：从仓库根 `shared/vectors/*.json` 复制到
  `android/core/crypto/src/test/resources/vectors/`；
- `check` 依赖该任务；CI 里再跑一次 `git diff --exit-code`，确保提交的副本与
  `shared/vectors` 一致（否则测试可能测的是旧向量）。
- 不使用符号链接（Windows 检出不可靠）。

**测试覆盖清单（每项都必须过）：**

| 向量文件 | 用例 | 断言 |
|---|---|---|
| `kdf.json` | `verifier` / `item_key` / `pair_kek` / `argon2id_kek` | 输出 base64url 完全相等 |
| `aead.json` | `item_ciphertext`（含 AAD）/ `wrapped_key` / `pair_blob` | 固定 nonce 下密文完全相等；解密回原文 |
| `signing.json` | 3 组签名串（GET+query / POST / POST） | Ed25519 签名 64B 完全相等 |
| `encoding.json` | master_key 的 base32/base64url、配对码展示/哈希 | 字节与字符串完全相等 |

**负面用例（同样重要）：**
- 篡改 `ct`/`nonce`/AAD → `AEADBadTagException`；
- 错误 item_id 派生 key → 解密失败；
- base32 输入含小写、`-`、空格、`=` → 解析成功且字节正确；
- base32 长度不是 32B → 明确报错（协议 §1.2 要求恰好 32B）。

---

## 3. 数据层

### 3.1 Room 表结构

```kotlin
@Entity(
    tableName = "items",
    indices = [Index("sync_state"), Index("version")],
)
data class ItemEntity(
    @PrimaryKey val id: String,          // ULID，26 字符（协议只要求 1..128B）
    val kind: String,                    // "totp"
    @ColumnInfo(name = "rp_id") val rpId: String,   // TOTP 恒为 "totp"（已定，§3.6）
    val ct: ByteArray,                   // 墓碑为空
    val nonce: ByteArray,                // 12B；墓碑为空
    val version: Long,                   // 服务端版本；0 = 尚未同步
    val updatedAt: Long,                 // LWW 时间（秒，已校时）
    val deletedAt: Long,                 // 0 = 未删
    @ColumnInfo(name = "sync_state") val syncState: Int,  // CLEAN/PENDING_UPSERT/PENDING_DELETE/REJECTED
    @ColumnInfo(name = "last_error") val lastError: String? = null,
)

@Entity(tableName = "meta")
data class MetaEntity(@PrimaryKey val key: String, val value: String)
```

**为什么不在 DB 里存明文 `label`/`issuer`：**
- 列表需要标题，但「解锁后一次性解密全部条目」对 TOTP 量级（几十~几百条）是毫秒级；
- 存明文 label 会把「你在哪些网站有账号」泄露给任何拿到 DB 文件的人（以及未来的备份/移植）；
- 取舍：内存里维护 `List<TotpItem>`，Room 只做持久化。若未来条目数 >2000 导致解锁卡顿，再加「本地加密索引列」（用 mk 派生的索引密钥加密 label），**不是**明文列。

**SQLCipher（可选项，v1 不做）：**
- 若要做全库加密：`net.zetetic:sqlcipher-android:4.19.1`，DB 口令用 Keystore 包裹的随机 32B；
- 代价：原生库 ABI + 16 KB 页对齐（`zipalign -c -P 16`）+ 迁移成本；
- 结论：v1 用 Room 明文库 + 只存密文；M3.3 再评估。

**迁移策略：** `exportSchema = true`，schema JSON 入库；任何字段变更都必须写 `Migration`，禁止 `fallbackToDestructiveMigration()`（会丢待推送条目）。

### 3.2 条目明文模型（保留未知字段）

协议 §5 要求「客户端必须保留未知字段（往返读写不丢）」。做法：**以 `JsonObject` 为唯一真相**，
只在编辑时覆盖已知 key，序列化时原样带回。

```kotlin
@JvmInline
value class TotpPlaintext(val json: JsonObject) {
    val label: String get() = json["label"]?.jsonPrimitive?.contentOrNull ?: ""
    val issuer: String get() = json["issuer"]?.jsonPrimitive?.contentOrNull ?: ""
    val secret: String get() = json["secret"]?.jsonPrimitive?.contentOrNull ?: ""
    val algorithm: String get() = json["algorithm"]?.jsonPrimitive?.contentOrNull ?: "SHA1"
    val digits: Int get() = json["digits"]?.jsonPrimitive?.intOrNull ?: 6
    val period: Int get() = json["period"]?.jsonPrimitive?.intOrNull ?: 30

    fun edited(label: String? = null, issuer: String? = null, notes: String? = null): TotpPlaintext {
        val m = json.toMutableMap()
        label?.let { m["label"] = JsonPrimitive(it) }
        issuer?.let { m["issuer"] = JsonPrimitive(it) }
        notes?.let { m["notes"] = JsonPrimitive(it) }
        m["kind"] = JsonPrimitive("totp")
        m["updated_at"] = JsonPrimitive(Clock.nowUnix())
        return TotpPlaintext(JsonObject(m))
    }

    fun encode(): ByteArray = Json.encodeToString(JsonObject.serializer(), json).encodeToByteArray()
}
```

**两个 `updated_at` 都要更新：** 明文里的 `updated_at`（协议 §5，业务时间）与外层同步用的
`updated_at`（协议 §4.6，LWW 时钟）语义不同但必须同时刷新；外层用 `max(now, prev+1)`（§3.4），
内层用 `now`。只改外层会让「条目内容时间」永远停在创建时间。

### 3.3 `items.json` ↔ Room 映射

| 协议字段（§4.6/§4.7） | Room 列 | 规则 |
|---|---|---|
| `id` | `id` | 客户端生成 ULID；创建后不变 |
| `kind` | `kind` | 固定 `totp`；服务端拒绝改写（协议 §4.6） |
| `rp_id` | `rp_id` | TOTP 恒为常量 `"totp"`（已定，§3.6）；两端同值 |
| `ct` | `ct` | base64url 解码后的字节；≤8192B |
| `nonce` | `nonce` | 12B；与 `ct` 同生命周期 |
| `version` | `version` | 服务端返回的版本；推送时作为 `base_version` |
| `updated_at` | `updated_at` | 客户端写入时间（**已校时**，见 §3.4） |
| `deleted_at` | `deleted_at` | 0/非 0；墓碑时 `ct=nonce=空` |
| — | `sync_state` | 本地状态机（§4.3） |
| — | `last_error` | 最近错误码（仅用于 UI，不含密文） |

**墓碑规则：**
- 本地删除：`deleted_at = now`、`ct/nonce = 空`、`sync_state = PENDING_DELETE`；UI 立即隐藏；
- 推送成功后：物理删除该行（服务端已有墓碑，其它设备会通过 pull 删除）；
- 收到远端墓碑：物理删除本地行（若本地是 `PENDING_*`，先保留本地，见 §4.4）。

### 3.4 LWW 与「秒级时间戳」陷阱

服务端 LWW 规则（协议 §4.6）：

1. 条目不存在 + `base_version==0` → 应用；
2. `base_version == 当前 version` → 无条件应用；
3. 否则 `updated_at > 服务端 updated_at` → 应用；
4. 否则（**含相等**）→ `conflict`。

**Android 必须补的规则：**
- 时间戳是**秒**。同一秒内两次编辑会产生 `updated_at` 相等 → 服务端判 conflict；
- 因此本地编辑时：`updatedAt = max(clock.nowUnix(), previousUpdatedAt + 1)`；
- 冲突后不要盲目重试（会一直相等）；先 pull 拿到服务端值，再按用户选择覆盖（`updatedAt = max(now, serverUpdatedAt + 1)`）。

**时钟来源：**
- 所有 `updated_at` / `X-Vkey-Ts` / TOTP 都使用 `ClockOffset.nowUnix()`（设备时钟 + 服务端偏移，§4.6）；
- 偏移未知（首次启动且离线）时用设备时钟，并在 UI 显示「未校时」。

### 3.5 全量重拉与回滚

协议 §4.7：`next < since` 表示服务端版本回滚（如从备份恢复）→ 客户端必须 `since=0` 全量重拉。

**实现约束：**
- `last_since` 与「本页 items 的应用」必须在**同一个 Room 事务**里提交，避免崩溃后跳版本；
- 全量重拉时：
  - `sync_state == CLEAN` 的本地行 → 用远端覆盖/删除；
  - `sync_state != CLEAN` 的本地行 → **保留**（用户未推送的修改不能丢），推完再拉；
- 全量重拉最多执行 1 次（防服务端持续回滚导致死循环）；再失败则报错给用户。

### 3.6 TOTP 的 `rp_id` 常量：`"totp"`

**结论（已定 2026-10-27）**：`kind = "totp"` 的条目，外层 `rp_id` 固定为字符串常量 `"totp"`。

| 项 | 值 / 规则 |
|---|---|
| 常量 | `"totp"`（5 字节 ASCII、小写、无前后缀、无末尾 `/`） |
| 适用范围 | 所有 `kind = "totp"` 条目**外层** `rp_id`；Linux（`vkey-hid`）与 Android **必须**使用同一常量 |
| 不由什么决定 | 不从 `issuer`/`label`/URL 推导，不做大小写归一化，不随 UI 语言或扫描来源变化 |
| 协议约束 | 协议 §4.6 要求 `rp_id` 1..255 字节且**创建后不可变** → 常量天然满足 |
| 明文放哪 | `issuer`/`label` 只在**密文内**的条目明文（协议 §5.1），所以 `rp_id = "totp"` 不泄露站点 |

**为什么用常量而不是站点域名：**

- TOTP 没有真正的 RP（relying party）概念。协议里 `rp_id` 对 `webauthn` 是站点域名，对 `totp`
  没有语义：`shared/examples/item-totp.json` 不含该字段，`kind=totp` 也没有定义其含义。
- 服务端只用 `rp_id` 做检索/去重（设计 §4.2），对所有 TOTP 用同一值不影响解密 ——
  `item_key` 只由 `id` 派生（协议 §1.1）。
- 若从 `issuer` 推导：同一站点在不同端的别名/大小写差异会写出不同 `rp_id`，而 `rp_id`
  **创建后不可变** → 永久分叉，且后写入方会被判 `status=rejected, reason=rp_id_mismatch`（协议 §4.6）。

**跨端一致性（硬要求）：**

1. 两端各自定义**单一常量出口**（Android：`const val TotpRpId = "totp"`；Linux 同名常量），
   **禁止**在调用点写字符串字面量 —— 便于审计「全仓只有一处定义」。
2. 新建 TOTP 条目时写入该常量；`POST /items` 的 `rp_id` 字段与 Room `rp_id` 列同值（§3.3）。
3. 读取方向宽容：服务端返回的 `kind=totp` 条目若 `rp_id != "totp"`（别的端/旧版本按其它规则写入），
   **照常落库与展示**（不丢弃、不改写、不回推），只在诊断页记一条「rp_id 不一致」。
   理由：读取不该因端间规则差异导致条目不可见；改写会被服务端判 `rp_id_mismatch`。
4. 校验点：`core:crypto` 之外再加一条单测断言「构造的 totp 上传体 `rp_id` 恒为 `"totp"`」，
   与协议向量无关但能防回归。

---

## 4. 同步引擎

### 4.1 同步循环（伪代码，≤30 行）

```kotlin
class SyncEngine(
    private val api: VkeyApi,
    private val repo: ItemRepository,
    private val clock: ClockOffset,
) {
    private val mutex = Mutex()

    suspend fun sync(): SyncResult = mutex.withLock {
        // 1) push：先推本地未同步，保证 base_version 语义
        val pending = repo.pending(limit = 500)
        var needPull = pending.isNotEmpty()
        if (pending.isNotEmpty()) {
            val resp = api.pushItems(pending.map { it.toUpload() })
            repo.applyPushResult(pending, resp)          // 单事务：状态 + version
            needPull = needPull || resp.results.any { it.status != "applied" }
        }
        // 2) pull：按 since 增量，处理回滚
        var cursor = repo.lastSince()
        var fullReloaded = false
        while (true) {
            val page = api.itemsSince(cursor)
            if (page.next < cursor) {                    // 协议 §4.7 回滚
                if (fullReloaded) error("server version rolled back twice")
                repo.resetCursor(); cursor = 0; fullReloaded = true; continue
            }
            repo.applyPage(page)                         // 单事务：upsert + cursor=next
            cursor = page.next
            if (page.items.size < PAGE_SIZE) break
        }
        SyncResult(ok = true, pulled = cursor)
    }
}
```

### 4.2 签名拦截器（最容易写错的地方）

协议 §3.1 的签名串：

```
METHOD + "\n" + RequestURI + "\n" + hex_lower(SHA256(body)) + "\n" + decimal(ts)
```

```kotlin
class SigningInterceptor(
    private val identity: DeviceIdentity,   // Ed25519 私钥 + token
    private val clock: ClockOffset,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val req = chain.request()
        val bodyBytes = req.body?.let { body ->
            Buffer().also { body.writeTo(it) }.readByteArray()
        } ?: ByteArray(0)
        val ts = clock.nowUnix()
        val uri = buildString {
            append(req.url.encodedPath)
            req.url.encodedQuery?.let { append('?').append(it) }
        }
        val signingString = "${req.method}\n$uri\n${sha256Hex(bodyBytes)}\n$ts"
        val sig = identity.sign(signingString.toByteArray(Charsets.UTF_8))
        return chain.proceed(
            req.newBuilder()
                .header("Authorization", "Bearer ${identity.tokenB64Url}")
                .header("X-Vkey-Ts", ts.toString())
                .header("X-Vkey-Sig", Base64Url.encode(sig))
                .build()
        )
    }
}
```

**必须遵守：**
- `RequestURI` 用 `encodedPath + "?" + encodedQuery`，**不要**用 `url.toString()`（会带 scheme/host）；
- body 哈希必须对「真正发出去的字节」计算：不要开请求体 gzip；不要用会在 `writeTo` 时改写的 `RequestBody`；
- GET 无 body：`SHA256("")` 常量（协议 §3.1 给了值）；
- 拦截器顺序：`SigningInterceptor` 必须在 `HttpLoggingInterceptor`（仅 debug）之前/之后都不影响 body，但**必须在重试拦截器之内**（每次重试重新签名、重新取 ts）。
- 429/401 重试时**必须重新生成 ts 和签名**，不能复用旧 header；
- `Base64Url.encode(...)` 必须**无填充**（协议 §1 补充表）；`Content-Type` 固定 `application/json; charset=utf-8`；
- body 用 `toRequestBody(mediaType)` 生成，序列化只做一次（不要在一个拦截器里 re-serialize，否则哈希与实际字节可能不一致）。

### 4.3 状态机与顺序

```
IDLE ──sync()──▶ PUSHING ──ok/无待推──▶ PULLING ──ok──▶ IDLE
                    │                      │
                    └──── 4xx/5xx ────────┴──▶ ERROR(可重试/不可重试) ──▶ IDLE
```

- **先 push 后 pull**：避免「本地未推送的修改」被远端旧版本覆盖（`base_version` 语义）。
- 推送到 `conflict` / `rejected`：
  - `conflict` → 直接做一次增量 pull（`since = last_since`）；正常情况下对方的写入 version 必然大于 `last_since`，会被拉到；若拉完仍未见到该条（异常/回滚），再触发一次全量重拉；
  - `rejected`（`kind_mismatch`/`rp_id_mismatch`）→ 本地条目视为损坏：标记 `REJECTED`，UI 显示「无法同步」，**不自动重试**。
- 推送按 **100 条/批**（协议上限 500）：单批失败只重传该批，降低 8 KiB×500 的重复流量。
- 任何一步失败都不推进 `last_since`。

### 4.4 失败重试与错误码

| 情况 | 判定 | 客户端动作 |
|---|---|---|
| 网络错误/超时 | `IOException` | 指数退避 1s→2s→4s→…→5min（±20% jitter），最多 5 次；后台任务交给 WorkManager |
| `401 invalid_token` / `missing_token` | 协议 §2.1 | **单飞**重新 `auth/token`（需要 mk + username）→ 换 token 后重试一次；再失败进入「需要重新登录」 |
| `401 ts_skew` | 协议 §2.1 | 重新校时（`GET /health` 读 `Date`）→ 重签重试一次 |
| `401 bad_signature` | 协议 §2.1 | 不重试；说明设备身份损坏 → 引导恢复/重新配对 |
| `400 invalid_*` | 协议 §2.1 | 不重试；记录错误码（脱敏），提示「客户端版本不兼容」 |
| `409 code_used` / `410 code_expired` | 配对 | UI 明确文案；让用户在旧设备重新生成 |
| `429 rate_limited` | 带 `Retry-After` | 按 `Retry-After` 等待；不要并发重试 |
| `5xx` | 服务端 | 退避重试；超过 5 次显示「服务器暂时不可用」 |

### 4.5 并发契约（必须同批登记到 `android/ASYNC.md`）

> 仓库规则要求「异步/并发程序必须登记并发契约」。Android 端第一版就包含前台同步、
> WorkManager、生物识别回调、剪贴板定时器，必须有一份 `android/ASYNC.md`，内容如下。

| # | 交互点 | 共享状态 | 保护手段 | 顺序契约 | 位置（计划） |
|---|---|---|---|---|---|
| 1 | 同步单飞 | `pending` 行、`last_since` | `Mutex`（`SyncEngine`） | 同一进程内同时只有一个 push/pull 循环 | `core/data/SyncEngine.kt` |
| 2 | 前后台同步去重 | WorkManager 队列 | `enqueueUniqueWork("vkey-sync", KEEP)` | 前台手动同步与后台任务不并行；后到者复用 | `core/data/SyncWorker.kt` |
| 3 | DB 事务 | `items` + `meta.last_since` | Room `withTransaction` | 条目与游标同事务提交，崩溃不跳版本 | `core/data/ItemRepository.kt` |
| 4 | mk 生命周期 | `MasterKeyHolder.mk` | `Mutex` + 解锁状态 | 锁定/解锁切换时先取消所有依赖协程，再清零 | `core/security/MasterKeyHolder.kt` |
| 5 | token 刷新 | `token`、`device_id` | `Mutex`（single-flight） | 401 时只允许一个 `auth/token`；成功后原子替换 token（协议偏差 7：旧 token 立即失效） | `core/network/TokenStore.kt` |
| 6 | 时钟偏移 | `offsetSeconds` | `@Volatile` + 原子写 | 只在主线程/同步协程写；读方容忍瞬时旧值 | `core/security/ClockOffset.kt` |
| 7 | 生物识别 | `Cipher` 实例 | 单次使用 | `CryptoObject` 只能 `init/doFinal` 一次；失败后必须重建 Cipher | `core/security/BiometricGate.kt` |
| 8 | 剪贴板清除 | 待清除的 code | 单个 `Job` | 新复制取消旧 Job；仅当剪贴板内容仍等于我们的值才清除 | `core/ui/ClipboardCleaner.kt` |
| 9 | 条目解密缓存 | 内存 `List<TotpItem>` | 只在解锁态存在 | 锁定时清空；不得写入磁盘 | `feature/items/ItemsViewModel.kt` |

### 4.6 时钟偏移与 ±120 秒窗口

- **为什么必须做**：协议 §3.1 要求 `|now - ts| <= 120`，设备时间偏 >2 分钟会**所有写接口 401**；TOTP 也依赖绝对时间。
- **校准方法**：`GET /api/v1/health`（免鉴权）读响应 `Date` 头：
  ```
  t0 = System.currentTimeMillis()（发请求前）
  t1 = System.currentTimeMillis()（收到响应后）
  offset = serverEpochSeconds - (t0 + t1) / 2 / 1000
  ```
  `Date` 只有秒级精度，误差 ±0.5s，足够。
- **时机**：冷启动、`ts_skew` 后、每 6 小时（前台）、手动「立即校时」。
- **UI**：`|offset| > 5s` 显示「设备时间偏差 Ns，验证码可能不正确」；`|offset| > 120s` 显示「无法同步，请开启自动时间」。
- **注意**：TOTP 倒计时用 `SystemClock.elapsedRealtime()`，不要用 `System.currentTimeMillis()` 做逐秒递减（用户改时间会让倒计时跳变）。

### 4.7 设备列表接口（协议增量：`GET /api/v1/devices`）

> **状态：已定（2026-10-27 拍板）**。这是协议 §4 的**增量**（现有只有 `devices/register`（§4.8）与
> `devices/revoke`（§4.9）），需同批补进 `shared/protocol.md` 与服务端实现。服务端未上线前，
> Android 设置页降级为「仅显示本机 + 本机吊销」，代码分支由「接口是否返回 404」决定，不做本地开关。

**契约：**

| 项 | 内容 |
|---|---|
| 方法 / 路径 | `GET /api/v1/devices` |
| 鉴权 | **签名**：协议 §3 三件套（`Authorization: Bearer <token>` + `X-Vkey-Ts` + `X-Vkey-Sig`） |
| 签名串 | `GET\n/api/v1/devices\nSHA256("")\n<ts>`（无 query、无 body；空体哈希用协议 §3.1 的常量） |
| 语义 | **只读**：仅返回本账号**未吊销**设备；不含公钥、token 摘要或任何可冒充凭据的材料 |
| 排序 | `created_at` 升序；本机不特殊排位，用 `current` 标记 |
| 副作用 | 鉴权通过时服务端刷新该设备的 `last_seen`（与其它签名接口一致） |

响应：

```json
{
  "devices": [
    {"id": "base64url(16B)", "name": "pixel", "platform": "android",
     "created_at": 1761436800, "last_seen": 1761437000, "current": true},
    {"id": "base64url(16B)", "name": "fedora", "platform": "linux",
     "created_at": 1761400000, "last_seen": 1761436900, "current": false}
  ]
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `devices` | array | 0..n；外层数组名沿用协议 §4.7 的 `items` 包装风格，便于统一解析 |
| `id` | string | `base64url(16B)`，与 `devices/revoke` 的 `device_id` 同值（协议 §3.3） |
| `name` | string | 注册/领取时上报的设备名（明文，服务端可见） |
| `platform` | string | `android` / `linux` / `windows` / `extension`，原样回显 |
| `created_at` | int | unix 秒 |
| `last_seen` | int | unix 秒，服务端最后成功鉴权时间 |
| `current` | bool | 本次请求所用 token 对应的设备为 `true`（恰一条为 `true`） |

**规则：**

- 吊销仍用协议 §4.9 `POST /api/v1/devices/revoke`（请求 `{"device_id": "..."}`）；列表页对任一条目
  （**含本机**）可吊销。吊销本机成功后：清空 `vault.bin` + DataStore → 回到引导页。
- **不返回** `pubkey_ed25519`、`token_hash`、`revoked_at`：已吊销设备直接不出现在列表里，
  客户端无需感知；展示面只需要「哪台、什么时候加的、最近什么时候活跃、是不是我」。
- 错误：401（鉴权）；405 `method_not_allowed`（本路径只允许 `GET`，`POST/PUT/DELETE` 一律 405）。
- 客户端不做本地缓存：列表页每次进入都拉取（数据量 ≤ 设备数，成本可忽略）；离线时展示上次结果 + 「离线」标记，不落盘。

---

## 5. 配对与引导

### 5.1 两条入口（对应设计 §3.1 / 协议 §4.10–§4.11）

| 入口 | 适用 | 用户输入 | 客户端动作 |
|---|---|---|---|
| **A. 手动输入 `master_key`** | 新账号第一台（或 Keystore 失效后恢复） | 52 字符 base32（`vkeyd init` 的 stdout） | `GET /policy` → 算 `verifier` → `POST /auth/token`（携带 Ed25519 公钥）→ 拿 token → `GET /items?since=0` |
| **B. 扫/输一次性配对码** | 已有设备给新设备授权 | `vkey://pair?...` 二维码或 13 组配对码 | `POST /pair/claim`（携带公钥）→ 拿 token + `blob` + `wrapped_key`/`pw_salt` → `HKDF(code,"vkey-pair",code_id)` 解 `blob` 得 mk |

**入口 A 的细节：**
- `username` 取 `/policy.username_hint`（协议 §4.1）；为空时允许手动输入（高级选项）；
- 若 `require_master_pw_enforced=true`：`auth/token` 返回 `wrapped_key`/`pw_salt`，必须再让用户输入主密码，解包并**常量时间比较**得到的 mk 与用户输入的 mk；不一致 → 报错（不得静默通过）。
- 不要把 `master_key` 写进日志、崩溃上报、剪贴板（默认不自动复制）。

**入口 B 的细节：**
- `pair/claim` 返回的 `blob` 布局：`nonce(12)||ct||tag`，无 AAD（协议 §10 偏差 2）；
- 解出 mk 后必须验证：长度 32B；`code_id` 与 QR 里的一致；随后 `GET /items?since=0` 用任意条目的 GCM tag 间接验证 mk 正确；
- **不要**在 claim 之后再调 `auth/token`：同一设备再次认证会覆盖 token（协议 §10 偏差 7），刚拿到的 token 会立即失效；
- 若 `require_master_pw_enforced=true`：必须再用主密码解 `wrapped_key` 并比较 mk（协议 §4.11），不得跳过。

### 5.2 QR 载荷格式（建议冻结）

```
vkey://pair?v=1
  &server=https%3A%2F%2F<YOUR_DOMAIN>
  &code=<base32(32B)，52 字符，无分组>
  &code_id=<pair-...>
  &name=<urlencoded 设备名提示，可为空>
  [&fp=sha256/<base64url(SPKI-SHA256)>]
```

解析规则：
- scheme 必须是 `vkey`，host 必须是 `pair`，`v` 必须为 `1`；
- `server` 必须 `https://`（拒绝 `http://`；局域网明文不在 v1 范围）；
- `code` 用宽容解析（协议 §1.2），解析后必须 32B；
- `code_id` **参与 KEK 派生**（`HKDF(code, salt="vkey-pair", info=code_id)`，协议 §1.1），所以必须与 `code` 一起来自 QR；`pair/claim` 响应会回显 `code_id`，再核对一次；
- `fp` 可选：自签证书场景的 **SPKI** 指纹（不是证书指纹）。注意：**pin 不能替代信任链**——自签模式需要自定义 `X509TrustManager`（只信任该 SPKI）+ 对该主机放行 hostname 校验，属于 M3.3 可选项；v1 默认只支持系统信任的证书（含 Let's Encrypt）。

**为什么不把 `master_key` 放进 QR**：配对码是一次性、10 分钟、服务端只存 hash 的短期凭据；`master_key` 是长期根密钥，任何二维码/截图/日志泄露都是永久泄露。

### 5.3 谁生成 QR

**只能由「已解锁、持有 `master_key` 的既有设备」生成。** 三条路径：

| 生成方 | 实现 | 说明 |
|---|---|---|
| Linux daemon（现状） | `vkey-hid pair-new`（`linux/src/main.rs:343`）扩展 `--qr`：终端 ASCII 或写 PNG | 已有代码已生成 code/code_id/blob，只差渲染 |
| Android 既有设备 | 设置 →「配对新设备」：调 `POST /pair/new`（签名）→ 页内显示 QR + 倒计时 | 需要 mk 在内存（已解锁） |
| 服务端 `/pair` 页 | **不生成** | 服务端不持有 code 明文（协议 §4.10 只存 `code_hash`），只做「安装入口 + APK 下载 + 说明」 |

`POST /pair/new` 的请求体按协议 §4.10：`{code_id, code, blob, pw_salt?}`；`code_id` 建议 `pair-<unix>-<4B hex>`（与 Linux 一致），TTL 600s，单次可用。

UI 上二维码页要显示：倒计时、`code_id`、服务器域名、「配对码只显示一次」。

### 5.4 引导状态机

```
[安装] → Welcome
  ├─ 我有恢复码 → RecoverKey(master_key) → PolicyCheck → AuthToken → InitialPull → RecoveryCodeCheck → Unlocked
  ├─ 扫码配对   → ScanPair → Claim → UnlockBlob → (PasswordCheck?) → InitialPull → RecoveryCodeCheck → Unlocked
  └─ 关于/服务器地址说明
```

`RecoveryCodeCheck` 是**强制**步骤（§5.5）：入口 B（扫码配对，用户手上没有恢复码）必须完成
「抄写 + 随机 2 组回填」，不通过不进入 `Unlocked`；入口 A 用户已手输恢复码（必然持有），
该步只做一键确认，不重复抄写。确认结果记在 DataStore 的 `recovery_code_confirmed`，
后续启动与解锁**不再**重复该步。

异常分支：
| 分支 | UI |
|---|---|
| `/policy` 不可达 | 「无法连接服务器」，可重试/改地址；不允许跳过（v1 无纯本地模式） |
| `require_master_pw=true` + `enforced=false` | 「服务端要求主密码但尚未设置：请在已登录设备执行 `vkey-hid passwd`」——按协议 §4.1 拒绝继续 |
| `code_not_found` / `code_used` / `code_expired` | 分别文案 + 「让旧设备重新生成」 |
| `code_id` 不匹配 | 「二维码与服务器响应不一致，可能扫错/被篡改」→ 拒绝 |
| TLS 证书错误 | v1：直接拒绝并显示原因（自签模式见 §5.2，M3.3 再支持） |
| `initial pull` 解密失败 | 「密钥不正确或数据损坏」→ 不写入 vault，回到引导 |

**落盘顺序（防半成品状态）：**
1. `auth/token` 成功（verifier 匹配）或 `pair/claim` + blob GCM tag 通过 → mk 已被密码学校验；
2. `GET /items?since=0` 拉到第一页；若页内有 `kind=totp` 条目，解密 1 条验证 GCM tag（空账号跳过）；
3. 全部通过后才写 `vault.bin` + DataStore（先写临时文件再 `rename`，避免掉电产生半个 vault）；
4. 失败则删除临时文件，不留下「有 token 但打不开」的状态。

> 空账号（0 条目）也能安全判定 mk：入口 A 由 `auth/token` 的 verifier 比较保证，入口 B 由
> `blob` 的 GCM tag 保证；不依赖「必须有条目才能验证」。

**`kind=webauthn` 的条目：** 协议同一账号下可能有 Linux 端写入的 WebAuthn 条目。Android v1
**保留但不展示**：同步时照常落库（`kind` 字段保留），列表过滤 `kind=totp`，在「关于/诊断」里
显示「另有 N 条 WebAuthn 条目，本版本不支持」。不要删除它们（删除会向服务端写墓碑，影响桌面端）。

### 5.5 恢复码（**强制**，已定 2026-10-27）

- **硬门禁**：首次引导必须抄写 + 校验恢复码，**校验不过不得进入主界面**（不是可跳过的提示）。
  引导状态机因此在 `Unlocked` 之前多一个 `RecoveryCodeSaved` 态（§5.4）。
- 展示：`base32(master_key)`（52 字符，按 4 字符分组显示，便于抄写；分组只是显示层，
  输入侧接受无分组/带空格/小写/`-`/`=`，见 §2.4 `b32DecodeTolerant`）；
- 校验：勾选「我已离线保存」+ 随机抽 2 组（每组 4 字符）让用户回填（防「直接下一步」）；
  回填错误 → 允许重试，重试 3 次后重新洗牌抽组，**始终不提供「跳过」入口**；
- 设置页提供「查看恢复码」：需要生物识别/密码 + 3 秒倒计时，禁止截屏（`FLAG_SECURE` 已全局）；
- 明确文案：「恢复码 = 你的全部数据。丢失且 Keystore 失效 = 永久无法解密。」
- 实现约束：恢复码字符串不写日志、不进 `vault.bin`（它可由 `mk` 随时重新编码得出）；
  抄写页 `FLAG_SECURE` 之外再加「禁止输入法学习/剪贴板自动收藏」（`importantForAutofill=no`）。

---

## 6. TOTP 实现

### 6.1 算法（RFC 6238 / RFC 4226）

```kotlin
fun totp(secret: ByteArray, atUnix: Long, period: Int, digits: Int, alg: String): String {
    val counter = atUnix / period
    val msg = ByteBuffer.allocate(8).putLong(counter).array()
    val mac = Mac.getInstance(
        when (alg.uppercase()) { "SHA256" -> "HmacSHA256"; "SHA512" -> "HmacSHA512"; else -> "HmacSHA1" }
    )
    mac.init(SecretKeySpec(secret, mac.algorithm))
    val h = mac.doFinal(msg)
    val off = h[h.size - 1].toInt() and 0x0f
    val bin = ((h[off].toInt() and 0x7f) shl 24) or
        ((h[off + 1].toInt() and 0xff) shl 16) or
        ((h[off + 2].toInt() and 0xff) shl 8) or
        (h[off + 3].toInt() and 0xff)
    return (bin % POW10[digits]).toString().padStart(digits, '0')
}
```

| 参数 | 取值 | 校验 |
|---|---|---|
| `algorithm` | `SHA1`（默认）/`SHA256`/`SHA512` | 其它值 → 拒绝导入并提示 |
| `digits` | 6（默认）/7/8 | 协议 §5.1：6..8 |
| `period` | 30（默认），15..120 | 协议只要求 >0；UI 对非常规值给警告 |
| `secret` | base32 解码后字节 | 建议 ≥10B（RFC 4226 最小 128-bit 推荐 20B）；<10B 警告 |

**测试向量**：RFC 6238 附录 B 的 6 组（SHA1/SHA256/SHA512 × 6/8 位）必须全过；再补
`shared/examples/item-totp.json` 的 secret 与参考实现（`oathtool --totp -b`）对拍。

### 6.2 `otpauth://` 解析

支持：
```
otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30
```

规则：
- `host` = `totp`（`hotp` → 明确拒绝：「第一版仅支持 TOTP」）；
- path 可能带 `Issuer:Account` 前缀；`issuer` 以 query 参数优先，二者不一致时保留 query 值并提示；
- `secret` 宽容解析（小写/空格/`-`/`=`），解码后必须非空；**存储前归一化为大写、无填充**（协议 §5.1）；
- `digits` 只接受 6..8、`period` 只接受 15..120，`algorithm` 只接受 SHA1/SHA256/SHA512；非法值 → 拒绝导入并说明原因（不要静默 clamp，避免用户以为导入成功）；
- 未知 query 参数：忽略，并在导入预览里列出「已忽略的参数」；
- `otpauth-migration://`（Google Authenticator 批量导出）**v1 不做**，UI 提示「请逐个导出/截图」，M3.3 再评估（protobuf 解析）。

### 6.3 扫码：ZXing vs ML Kit（离线判断）

| 方案 | 离线 | 依赖 | 体积 | 结论 |
|---|---|---|---|---|
| **ZXing core 3.5.4 + CameraX** | ✅ 完全离线 | 无 GMS | 很小（~0.5MB 代码） | **v1 默认** |
| ML Kit **bundled** `com.google.mlkit:barcode-scanning:17.3.0` | ✅ 离线（模型静态链接） | 不需要 Play services | **+约 2.4MB** | 备选（识别率/弱光更好时再换） |
| ML Kit **unbundled** `play-services-mlkit-barcode-scanning` | ❌ 需 Play services 下载模型 | 需 GMS | 小（~200KB） | **不用**（国产 ROM 无 GMS） |

（依据：附录 A-5）

实现要点：
- CameraX `ImageAnalysis`（`STRATEGY_KEEP_ONLY_LATEST`），`ImageProxy` → YUV → `PlanarYUVLuminanceSource` → `MultiFormatReader`（只开 `QR_CODE`）；
- 限制 5 fps，避免发热；识别到后立即 `close()`；
- 手电筒开关、相册识别（`InputImage.fromBitmap` 不存在于 ZXing；用 `Bitmap` 转 luminance）；
- 权限拒绝 → 显示「手动输入」入口（`otpauth://` 粘贴 + 配对码手输）；
- 同一相机页同时支持 `vkey://pair` 与 `otpauth://`，按 scheme 分发。

### 6.4 展示、复制、防截屏

| 项 | 做法 |
|---|---|
| 验证码展示 | 大字号、等宽、按 3 位分组；环形倒计时（`elapsedRealtime`） |
| 刷新 | 每秒重算；跨周期时触觉反馈（可选） |
| 复制 | `ClipboardManager` + `ClipDescription.EXTRA_IS_SENSITIVE`（API 33+），Toast「已复制，30 秒后清除」 |
| 自动清除 | 30s 后，仅当剪贴板内容仍等于我们复制的值才清；后台无法读剪贴板时，标记并在下次 `onResume` 清除 |
| 防截屏 | `window.setFlags(FLAG_SECURE)`（全局，含最近任务缩略图） |
| 防误触泄漏 | 详情页 30s 无操作自动回到列表？不做（体验差）；改为锁屏超时（设置项，默认 5 分钟） |
| 无障碍 | 验证码文本可被 TalkBack 读出——这是**已知取舍**（可访问性优先）；设置里提供「隐藏验证码朗读」不现实（文本节点仍可读），文档明示 |

`FLAG_SECURE` 的副作用：Android 13+ 的「最近任务」缩略图为空白，属预期；相机预览不受影响。

### 6.5 时间不准导致验证码错

- 展示页显示「时间已校准 ±Ns」或「未校准」；
- `|offset| > 5s` 时在列表顶部显示黄色横幅；
- 提供「去系统设置开启自动时间」的跳转（`Settings.ACTION_DATE_SETTINGS`）；
- 校验码在 `period` 边界附近（剩余 <3s）时，复制动作提示「即将过期，建议等待下一码」——可选，避免误操作。

---

## 7. UI 结构

### 7.1 页面清单

| 路由 | 页面 | 进入条件 | 关键交互 | 空态 / 错误态 |
|---|---|---|---|---|
| `/welcome` | 引导首页 | 无 vault | 「我有恢复码」「扫码配对」「服务器说明」 | 服务器不可达 → 显示地址 + 重试 |
| `/recover` | 恢复码输入 | 无 vault | 52 字符输入、自动分组、粘贴 | 长度/字符错误；policy 拒绝 |
| `/pair` | 扫码配对 | 无 vault | 相机、手输 13 组、粘贴 `vkey://` | 权限拒绝；`code_*` 错误映射 |
| `/unlock` | 解锁 | 有 vault，未解锁 | 自动弹生物识别；「使用主密码」；错误次数退避 | 密钥失效 → 恢复入口；锁定 30s |
| `/items` | 列表 | 已解锁 | 搜索、下拉同步、点按复制、长按详情 | 空态「扫码或手动添加」；离线/待同步/错误 chip |
| `/items/{id}` | 详情 | 已解锁 | 大码 + 倒计时 + 复制 + 编辑 + 删除 | 解密失败 → 「密钥不匹配」+ 恢复 |
| `/add` | 添加 | 已解锁 | 扫码 / 手动 / 粘贴 `otpauth://`；预览后保存 | 重复条目提示；字段非法提示 |
| `/settings` | 设置 | 已解锁 | 服务器、账号、同步、安全、恢复码、关于 | — |
| `/settings/devices` | 设备 | 已解锁 | `GET /devices`（§4.7）列出设备：名称 / 平台 / 创建时间 / 最近活跃 / 「本机」标记；任一设备可吊销（§4.9），本机吊销后清空 vault 回引导 | 接口未上线（404）→ 明示「仅显示本机」；离线 → 上次结果 + 离线标记 |
| `/settings/security` | 安全 | 已解锁 | 生物识别开关、锁定超时、截屏保护说明、更换主密码（可选） | — |

### 7.2 应用级状态

```kotlin
sealed interface AppState {
    data object Onboarding : AppState
    data class Locked(val reason: LockReason) : AppState      // ColdStart/Timeout/Manual/KeyInvalidated
    data class Unlocked(val items: List<TotpItem>) : AppState
    data class Fatal(val reason: FatalReason) : AppState      // PolicyNeedsSetup/TlsPinMismatch/...
}
```

- 冷启动默认 `Locked(ColdStart)`；`onStop` 超过「锁定超时」→ `Locked(Timeout)`；
- 切换后台时**不**立即清空（否则每次切回都要指纹），按设置项；
- `KeyInvalidated` → 只能走恢复码/重新配对。

### 7.3 空态、错误态（必须写文案）

| 场景 | 文案要点 |
|---|---|
| 列表为空 | 「还没有验证码。扫描二维码或手动添加。」+ 两个按钮 |
| 同步中 | 顶部细进度条，不阻塞列表 |
| 离线 | 「离线，显示本地数据」+ 上次同步时间 |
| 待推送 N 条 | 「N 条待同步」点击可重试 |
| `ts_skew` | 「设备时间与服务器相差 Ns，已自动校准」 |
| `invalid_token` | 「登录已失效，请重新解锁」 |
| 密钥失效 | 「本机密钥已失效（可能更换了锁屏/指纹）。输入恢复码即可恢复，数据未丢失。」 |
| `policy` 要求主密码但未设置 | 「服务端要求主密码，但尚未设置。请在已登录设备运行 `vkey-hid passwd`。」 |
| 服务器证书不匹配 | 「服务器证书与配对时不一致」+ 指纹对比 + 「仍要连接」需二次确认（仅自签模式） |

### 7.4 主题与无障碍

- Material 3；默认跟随系统深浅色；动态取色（Android 12+）默认启用，低版本回退品牌色（见 §7.5）；
- 字号：验证码至少 `displayLarge`；支持系统字体缩放 200% 不截断（用 `autoSize`/可换行布局）；
- 触控目标 ≥48dp；对比度 ≥4.5:1；
- TalkBack：按钮有 `contentDescription`；倒计时用 `liveRegion = Polite` 且只在剩余 5s 时播报，避免每秒刷屏；
- 不用颜色单独表达状态（同步状态同时用图标 + 文案）；
- 动效：尊重「移除动画」设置。

### 7.5 主题模式与语言（2026-10-28 实施）

**偏好存储**：与同步地址、自动锁定同用一个 `SharedPreferences`（文件名 `vkey_settings`）。

| 键 | 取值 | 默认 | 读取时机 |
|---|---|---|---|
| `theme_mode` | `system` / `light` / `dark` | `system` | `VkeyTheme` 每次重组（`LocalContext`） |
| `language` | `system` / `zh` / `en` | `system` | `MainActivity.attachBaseContext`（冷启动 / 重建） |

枚举与读写集中在 `vault/AppSettings.kt`（`ThemeMode` / `LanguageMode` + `fromStorage`），非法值一律回退 `system`。

**主题切换机制**：`ui/theme/Theme.kt` 的 `VkeyTheme(mode, content)` 先把 mode 解析成 `darkTheme`
（`SYSTEM` → `isSystemInDarkTheme()`），选完配色后用 `Surface(background)` 兜底整屏背景。
设置页改 mode **只改 Compose 状态 + 落盘**、不重建 Activity，重组即生效；系统栏图标明暗由
`WindowCompat.getInsetsController(...).isAppearanceLightStatusBars / isAppearanceLightNavigationBars` 同步。
窗口级 `Theme.Vkey` 另备 `values-night` 变体，只用于「跟随系统」时冷启动首帧不闪白/闪黑。

**语言切换机制**：不引入 appcompat（依赖清单里没有），改用 `attachBaseContext` 包装 configuration：
`i18n/LocaleSupport.wrap(base, mode)` 对 `zh` / `en` 用 `createConfigurationContext`（`setLocales` +
`setLayoutDirection`）并 `Locale.setDefault`；`system` 原样返回 base，并把进程默认 locale 复位成系统值
（否则「切回跟随系统」后 `Locale.getDefault()` 仍停在上一次的覆盖值）。
设置页切换语言 → 写偏好 → `recreate()`：新 Activity 在 `attachBaseContext` 读到新值，`getString` /
`stringResource` 立即换语言；vault 由 `onCreate` 从磁盘重读，数据不丢（重建后会重新走一次解锁）。
`android:configChanges` 不含 `locale`，因此「跟随系统」时系统切语言由系统自动重建。

**文案资源**：`res/values/strings.xml` 为中文（默认），`res/values-en/strings.xml` 为英文，两份 key 一一对应
（各 160 条），带参数的统一用 `%1$s` / `%1$d`。非 UI 层（`crypto` / `net` / `sync`）的 `require` 与异常
消息只面向开发者，统一英文；用户可见错误集中在 `ui/SyncScreen.kt` 的 `describeFailure(context, t)`，
按服务端 `code` 映射到字符串资源（含 `not_configured` / `stale_write`）。

**动态取色回退策略**：`Build.VERSION.SDK_INT >= 31`（Android 12）→ `dynamicLight/DarkColorScheme(context)`；
否则 → `ui/theme/Color.kt` 的自定义冷灰蓝品牌色（明暗两套，正文 ≥ 4.5:1、控件边框 ≥ 3:1）。
二维码区域例外：固定纯白底 + 黑模块（扫码器依赖高对比度），不随主题变化；
扫码页的相机覆盖层也不跟随主题（背景永远是相机预览），其颜色常量统一放在 `Color.kt`。


---

## 8. 安全清单

| 项 | 措施 | 验收 |
|---|---|---|
| 本地不落明文 | DB 只存 `ct/nonce/元数据`；明文 JSON 只在内存；`vault.bin` 只存 Keystore 包裹后的密钥材料 | `adb shell run-as ... strings databases/*.db` 搜不到 secret/label |
| 备份 | `android:allowBackup="false"` + `android:fullBackupContent="false"` + `dataExtractionRules` 排除 `cloud-backup` 与 `device-transfer`（Android 12+ 仅 `allowBackup=false` 不足以阻止 D2D） | `adb backup` 无数据；换机克隆不含 vault/DB |
| 日志 | release 关闭 `HttpLoggingInterceptor`；自定义拦截器只记 method/path/status；异常信息不含 body | `adb logcat` 搜不到 token/secret/mk |
| 崩溃上报 | **默认无**；若未来接入，必须 opt-in + 去除 breadcrumbs/自定义字段 | 设置页可见开关，默认关 |
| root/调试检测 | 仅提示，不阻断（可绕过、误报高）；`Debug.isDebuggerConnected()` 在 release 只记一条本地事件；不用 Play Integrity（自建/无 GMS） | 设置页「设备完整性：已 root（仅提示）」 |
| 截屏/录屏 | 全局 `FLAG_SECURE` | `adb shell screencap` 得到空白/失败 |
| 剪贴板 | `EXTRA_IS_SENSITIVE` + 30s 清除 | 复制后 30s 剪贴板为空；Android 13 预览不显示内容 |
| 网络 | 禁明文（`usesCleartextTraffic=false`）；默认只信任系统 CA；自签模式（M3.3 可选）用自定义 `X509TrustManager` 只信任 QR 里的 SPKI（pin ≠ 信任链） | 抓包无法降级到 http；错误证书被拒 |
| 输入 | 密码框 `KeyboardType.Password`；密钥类输入禁用 autofill（`importantForAutofill=no`）；不在 `contentDescription` 里放密钥 | 输入法不出现自动填充建议 |
| 内存 | 密钥用 `ByteArray`，锁定/退出时 `fill(0)`；避免把 secret 放 `String` 长期持有 | 代码审查项 |
| 导出 | 恢复码只在设置页、认证后显示；不自动复制 | — |
| 依赖 | 无 GMS/Firebase；release 开 R8 + `shrinkResources`；`debuggable=false` | `aapt dump badging` 检查 |
| 设备吊销 | 列表（`GET /devices`，§4.7）后按协议 §4.9 吊销任一设备（含本机） | 列表能显示其它设备；吊销后该设备 token 立即失效（再同步返回 401） |
| 传输重放 | 协议已知限制：±120s 内可重放（协议 §3.3），客户端无法根治；靠 TLS + token 不落盘（Keystore 包裹） | 文档明示，不宣称「防重放」 |

**备份配置示例：**

```xml
<!-- res/xml/data_extraction_rules.xml -->
<data-extraction-rules>
    <cloud-backup><exclude domain="root" path="." /></cloud-backup>
    <device-transfer><exclude domain="root" path="." /></device-transfer>
</data-extraction-rules>
```

```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config" />
```

---

## 9. 构建与分发

### 9.1 目录结构（`android/` 放仓库根，与设计 §10 一致）

```
android/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── gradle/libs.versions.toml
├── gradle/wrapper/{gradle-wrapper.jar,gradle-wrapper.properties}
├── app/                          # 壳：Application、MainActivity、导航、DI 容器
│   ├── src/main/java/cn/xiaoqiong0v0/vkey/
│   ├── src/main/res/xml/{data_extraction_rules,network_security_config}.xml
│   └── src/androidTest/          # Keystore/Biometric/Room 仪器测试
├── core/
│   ├── crypto/                   # 纯 JVM：HKDF/AEAD/Ed25519/Argon2/Base32 + 向量测试
│   ├── model/                    # DTO + TotpPlaintext(JsonObject) + ULID
│   ├── data/                     # Room、Repository、SyncEngine、VaultStore
│   ├── network/                  # OkHttp、SigningInterceptor、VkeyApi
│   ├── security/                 # KeystoreKeyStore、BiometricGate、ClockOffset、MasterKeyHolder
│   └── designsystem/             # 主题、通用组件
├── feature/
│   ├── onboarding/  unlock/  items/  add/  pair/  settings/
└── scripts/
    ├── sync-vectors.sh           # shared/vectors → core/crypto/src/test/resources
    ├── build-release.sh          # assembleRelease + apksigner verify + sha256
    └── upload.sh                 # 见 §9.3（dry-run 默认）
```

**模块划分的硬约束：**
- `core:crypto` **不得**依赖 Android SDK（`android { }` 里不引 `appcompat` 等），这样向量测试可以在 JVM 上跑；
- `core:data` 不直接依赖 OkHttp；网络通过 `core:network` 的接口注入，便于用假服务器测同步；
- `feature:*` 之间不互相依赖，只依赖 `core:*`。

### 9.2 Gradle 关键配置

```kotlin
android {
    namespace = "cn.xiaoqiong0v0.vkey"
    compileSdk = 36

    // 签名材料只在发布机/CI 注入：环境变量齐全才创建 release signingConfig。
    // 缺省时 release 产出 unsigned APK（本机仍可跑 assembleRelease 验证 R8），
    // debug 构建永远不需要签名材料，也不会因为缺环境变量而失败。
    val releaseKsPath = System.getenv("VKEY_ANDROID_KS")?.takeIf { it.isNotBlank() }

    defaultConfig {
        applicationId = "cn.xiaoqiong0v0.vkey"   // 永久不变；变了就是另一个 App
        minSdk = 26
        targetSdk = 36
        versionCode = 30100                      // 0.3.1.0 → 30100（major*10000 + minor*100 + patch）
        versionName = "0.3.1"                    // 对应里程碑 M3.1
    }
    signingConfigs {
        if (releaseKsPath != null) {
            create("release") {
                storeFile = file(releaseKsPath)
                storePassword = System.getenv("VKEY_ANDROID_KS_PASS")
                keyAlias = System.getenv("VKEY_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("VKEY_ANDROID_KEY_PASS")
            }
        }
    }
    buildTypes {
        debug {
            isMinifyEnabled = false
            // M3.1 验收 4 的「模拟密钥失效」入口只在 debug 存在
            buildConfigField("boolean", "ENABLE_KEY_FAULT_INJECTION", "true")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            buildConfigField("boolean", "ENABLE_KEY_FAULT_INJECTION", "false")
            // null = 不挂签名 → 产出 unsigned APK；有环境变量时自动挂上
            signingConfig = signingConfigs.findByName("release")
        }
    }
    buildFeatures { buildConfig = true }   // buildConfigField 需要显式开启
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
```

**签名启用的判定（必须这样写）：**

- 只登记 `VKEY_ANDROID_KS`（keystore 路径）作为「是否具备签名条件」的开关；口令/别名缺失时
  `assembleRelease` 会在签名阶段报错，属预期（发布机必须给全 4 个变量）。
- **不要**用 `?: error("VKEY_ANDROID_KS")`：那会让 `assembleDebug`、单元测试、IDE 同步在没有
  签名材料的环境直接失败，等于把「发布前置」变成「开发前置」。
- CI 语义：`VKEY_ANDROID_KS` 存在 → release 已签名 → 才继续跑 `apksigner verify`；不存在 → 只跑
  `assembleDebug` + `:core:crypto:test`（见 §9.3 CI 片段）。

`versionCode` 规则：`major*10000 + minor*100 + patch*10`（M3.1.0 → `30100`）。升级必须递增，否则覆盖安装失败。

### 9.3 签名与 CI 产物上传

**签名（与设计 §3.1 一致：私钥不进服务端）**

```bash
# 一次性：生成自签 keystore（放在仓库外，0600）
keytool -genkeypair -v -keystore ~/.vkey/android-release.jks \
  -alias vkey -keyalg RSA -keysize 4096 -validity 10000
```

- CI/本机通过环境变量注入口令；`keystore.properties` 不入库；
- **必须备份 keystore**：丢失后无法覆盖安装（同包名不同签名 → 需先卸载，本地 vault 若未备份则丢）；
- 构建校验：

```bash
./gradlew :app:assembleRelease
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
zipalign -c -P 16 -v 4 app/build/outputs/apk/release/app-release.apk   # 有 native 库时必查
sha256sum app-release.apk
```

**上传到服务器 `/dl/`（新增脚本，dry-run 默认，遵守仓库部署纪律）**

```bash
# android/scripts/upload.sh  （或 server/deploy/upload-android.sh）
# 默认 dry-run；--apply 才执行
REMOTE="${REMOTE:-<SSH_USER>@<SERVER_IP>}"
REMOTE_DIR="${REMOTE_DIR:-/home/ecs-user/work/vkey}"
ARTIFACTS="${ARTIFACTS:-$REMOTE_DIR/data/artifacts}"   # systemd WorkingDirectory=data → 默认 ./artifacts
# 1) 校验 APK 签名与哈希
# 2) scp vkey-android.apk → $ARTIFACTS/vkey-android.apk.new
# 3) 远端：mv 覆盖；
#    cd $ARTIFACTS && sha256sum -b vkey-android.apk vkey-hid-linux-*.tar.gz > SHA256SUMS
#    （按白名单逐个列，禁止 `sha256sum -b *`：会把 SHA256SUMS 自身算进去，形成自引用）
# 4) curl -fsS https://$DOMAIN/dl/SHA256SUMS | grep vkey-android.apk
```

说明：
- 产物名必须是 **`vkey-android.apk`**（协议 §4.12 的占位名），且必须出现在 `SHA256SUMS` 里，否则 `/dl/*` 返回 404；
- 服务端只读分发，`vkeyd` 不参与构建；
- 现有 `server/deploy/deploy.sh` 只部署二进制；**不要**把 APK 构建塞进去，避免部署脚本依赖 Android SDK。

**CI（可选，建议 GitHub Actions 或本地脚本）**

```yaml
# .github/workflows/android.yml（示意）
- uses: actions/setup-java@v4
  with: { distribution: temurin, java-version: '17' }
- run: ./gradlew :core:crypto:test :app:assembleRelease
- run: apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
```

> 仓库当前没有 CI；是否引入由用户决定。至少要有「本地 `./gradlew check` + 上传脚本 dry-run」两道门禁。

### 9.4 自建分发 vs Play 上架

| 项 | 自建 `/dl/vkey-android.apk` | Google Play |
|---|---|---|
| 签名 | 自签 keystore（我们持有） | Play App Signing（平台持有最终签名密钥） |
| 产物 | APK | AAB |
| 安装 | 需「安装未知应用」授权；Play Protect 可能提示 | 商店安装 |
| targetSdk | 自主 | **2026-08-31 起必须 API 36**（附录 A-9） |
| 16 KB 页 | 2027-02-01 起 targetSdk 35+ 必须支持（附录 A-8） | 同 |
| 合规 | 无 | Data safety、隐私政策、内容分级 |
| 更新 | 手动下载覆盖 / 自建检查 | 自动更新 |
| 风险 | 假冒包、用户装错来源 | 审核/下架、账号依赖 |

**结论**：v1 只做自建；Play 作为后续可选项，代码上不需要为 Play 改架构（AAB 只是打包格式）。

**自更新（M3.3 可选）**：设置页「检查更新」→ `GET /dl/SHA256SUMS` → 与本地 `versionName`/APK 哈希对比 → 用浏览器打开 `/dl/vkey-android.apk`。若要在应用内安装，需要 `REQUEST_INSTALL_PACKAGES` + `FileProvider` + `ACTION_VIEW`，会触发 Play 政策审查，自建分发才考虑。

---

## 10. 里程碑拆分与验收

### M3.1 最小可用（本地 TOTP，不联网）

**范围：**
- Gradle 工程、模块骨架、`core:crypto`（HKDF/AEAD/Ed25519/Argon2/Base32）；
- Room + 仓储；`TotpPlaintext(JsonObject)`；
- 手动输入 `master_key` 引导（仅本地校验 32B，不连服务器）；
- 手动添加 / 扫码 `otpauth://` / 列表 / 详情 / 删除；
- Keystore vault + 生物识别（或设备凭据）解锁；
- `FLAG_SECURE`、剪贴板 30s 清除、恢复码强制保存。

**验收（全部可测）：**
1. `./gradlew :core:crypto:test` 通过 `shared/vectors` 四个文件**逐字节**比对；
2. RFC 6238 官方向量（SHA1/256/512，6/8 位）全过；与 `oathtool --totp -b` 对拍 3 个时间点一致；
3. 飞行模式冷启动 → 解锁 → 添加条目 → 进程杀死重开 → 条目仍在且验证码正确；
4. 用 **debug 构建内置的「模拟密钥失效」按钮**（`BuildConfig.ENABLE_KEY_FAULT_INJECTION`，仅 debug 可见：
   删除 Keystore alias + 丢弃 `vault.bin` 后重启进程）→ 重启 App 显示恢复流程 → 输入恢复码后条目仍能解密；
   release 构建不包含该入口（不靠手工操作设备，避免「测过但没记录」）；
5. `adb shell screencap` 无法截到验证码页（黑屏/失败）；复制后 30s 剪贴板为空；
6. `aapt dump badging` 确认 `targetSdkVersion=36`、`minSdkVersion=26`、`debuggable=false`（release）。

### M3.2 同步与配对（联网）

**范围：**
- `core:network`（OkHttp + 签名拦截器）、`/policy`、`auth/token`、`items` push/pull、`pair/claim`；
- 时钟校准、`ts_skew` 自动恢复、token 刷新单飞；
- WorkManager 周期同步 + 前台手动同步 + 下拉刷新；
- 冲突处理、墓碑、全量重拉、错误码映射；
- **设备列表（`GET /devices`，§4.7）与吊销（协议 §4.9）**：设置页列出本账号设备、标记本机、吊销任一设备；
- 配对 QR（Android 生成 + 扫描）、`vkey-hid pair-new --qr`（Linux 侧小改）。

**验收：**
1. 端到端：Android 写 TOTP → Linux `vkey-hid sync` 解密得到同一 secret；反向亦然；
2. 配对：`vkey-hid pair-new` 生成码 → Android 扫码领取 → 立即 pull 成功；同一码第二次领取返回 `409`，UI 显示「已使用」；
3. 时钟：把设备时间调快 10 分钟 → 同步收到 `ts_skew` → 自动校时后重试成功；TOTP 仍与参考实现一致；
4. 冲突：两端改同一条（不同 `updated_at`）→ 两端最终一致；落败写入在服务端 `item_conflicts`（用 sqlite 查询验证）；
5. 断网：飞行模式下新增/删除 5 条 → 恢复网络后一次同步全部生效，无重复、无丢失；
6. 回滚：手工把服务端 `seq` 调小（测试库）→ 客户端触发一次 `since=0` 全量重拉，本地 `PENDING_*` 不丢；
7. 批量：500 条推送、1000 条分页拉取（用 fake API 单测覆盖）。

### M3.3 生物识别与打磨

**范围：**
- StrongBox（可用时）、认证绑定密钥的完整分支（API 26–29/30+）、`setUnlockedDeviceRequired`；
- 设置页：设备列表打磨（§4.7 的展示与确认流）、同步状态、恢复码查看、主密码设置（可选）；
  （设备列表与吊销的**功能实现**归 M3.2；M3.3 只做交互与文案打磨）
- 无障碍、字体缩放、深色模式、错误文案；
- 自签证书 SPKI pin（QR `fp`）；
- release 签名 + `/dl` 上传 + 安装验证；
- 可选：`otpauth-migration://` 导入、应用内更新。

**验收：**
1. API 26/30/33/36 模拟器 + 至少 1 台国产 ROM 真机（小米/OPPO/vivo 任一）通过解锁、同步、扫码、后台恢复；
2. TalkBack 走查清单（列表/详情/复制/删除/错误提示）无未标注控件；
3. 字体 200% 下详情页验证码不被截断；
4. `apksigner verify`、`zipalign -c -P 16` 通过；`/dl/SHA256SUMS` 含 `vkey-android.apk` 且哈希一致；
5. 干净设备安装 → 配对 → 同步 → 卸载重装 → 用恢复码恢复 → 数据完整。

---

## 11. 风险清单（逐条缓解）

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| 1 | **国产 ROM 后台限制/自启动管理** | WorkManager 周期任务被推迟数小时；「同步不及时」 | 同步以「打开 App / 下拉刷新」为主路径；WorkManager 只做 best-effort；设置页提供「忽略电池优化」跳转与说明；不做「保证实时」承诺 |
| 2 | **Keystore 密钥失效**（刷机、恢复出厂、移除锁屏、生物识别变更、部分 ROM 升级） | 默认模式下 `mk` 不可解 → 全部数据不可读 | 强制保存恢复码（§5.5）；错误页引导恢复；Room 密文不删；可选主密码作为第二把钥匙。`setInvalidatedByBiometricEnrollment(false)` **只降低「新增指纹」触发失效的概率**；**锁屏被移除/更改、恢复出厂、Keystore 损坏（含部分 ROM 升级）仍会失效** —— 不得据此认为「不会失效」 |
| 3 | **设备时间不准** | 同步全部 401 `ts_skew`；TOTP 错 | 启动/异常时用 `/health` 的 `Date` 校时；横幅提示；TOTP 用校时后的时间；倒计时用 `elapsedRealtime` |
| 4 | **Ed25519 无法硬件绑定** | 设备私钥是软件密钥，root/注入可窃取 | Keystore AES 包裹 + 生物识别门控；签名瞬间才解包；UI 明示「软件密钥」；高风险用户可用主密码模式 |
| 5 | **自签 APK 安装提示/假冒包** | 用户装不上或装到假包 | 文档给 SHA256；`/dl/SHA256SUMS` 校验；应用内显示签名指纹；引导页写明官方下载域名 |
| 6 | **WorkManager 15 分钟最小周期 + Doze** | 后台同步延迟 | 同上；前台同步为主；不用 `AlarmManager` 精确闹钟（权限/耗电） |
| 7 | **Argon2id 纯 Java 慢 / 低端机 OOM** | 主密码解锁 3–10s，甚至 OOM | 参数取 `/policy.kdf`；解锁页显示进度；实测目标 ≤3s（中端机）；超时则评估换 Signal argon2（native，需 16 KB 对齐 + ABI） |
| 8 | **16 KB 页面（Android 15+ 设备，Play 2027 强制）** | native 库不兼容会崩溃/无法上架 | v1 纯 Java（BC）无 native 库；若引入 native，必须 NDK r28+ 并用 `zipalign -c -P 16` 校验 |
| 9 | **`rp_id` 对 TOTP 未定义** | 跨端创建不一致；服务端拒绝改写 | 已定常量 `"totp"`（§3.6），两端同值；常量需同批补进 `protocol.md`，否则 Linux 侧会写出旧规则的值 |
| 10 | **设备列表接口是协议增量** | 服务端/协议未落地前，手机上看不到其它设备 | 已定新增 `GET /devices`（§4.7）；落地前设置页降级为「仅显示本机」，落地后无需改数据层 |
| 11 | **协议重放窗口 ±120s** | token 泄露后可重放 | 服务端已知限制；客户端保证 token 不落明文；TLS；不宣称更强 |
| 12 | **备份恢复导致「有 DB 无 Keystore」** | 换机克隆后打不开 | `allowBackup=false` + `dataExtractionRules` 排除；检测到 vault 无法解密 → 恢复码流程 |
| 13 | **Compose/AGP/KSP 版本组合** | 构建失败 | §1.3 版本锁定；M3.1 第一门禁；失败按 §12.2 第 8 项降级 |
| 14 | **用户忘记恢复码 + Keystore 失效** | 数据永久丢失 | 这是零知识架构的固有代价；引导页强提示 + 抄写校验；可选主密码；文档写明「我们无法帮你恢复」 |

---

## 12. 决策状态

### 12.1 已定（2026-10-27 用户拍板）

| # | 事项 | 决定 | 在本文的落点 |
|---|---|---|---|
| 1 | 恢复码是否强制 | **强制**：首次引导必须抄写 + 回填校验，未通过不得进入主界面 | §2.2 冲突 3、§5.4 `RecoveryCodeCheck`、§5.5 |
| 2 | `minSdk` | **26（Android 8.0）**；`targetSdk/compileSdk 36` | §1.2、§9.2 |
| 3 | TOTP 的 `rp_id` | 固定常量 **`"totp"`**，Linux / Android 同值 | §3.6、§2.2 冲突 4 |
| 4 | `GET /api/v1/devices` | **新增**（签名、只读），设置页可列设备并按协议 §4.9 吊销 | §4.7、§7.1、§10 M3.2 |

### 12.2 实施期决定（不阻塞开工，实施者按建议执行即可）

> 以下 6 项由实施者在落地时按「建议」列执行，**不需要**再回流确认；若改变建议（例如换 pin 格式），
> 需在对应里程碑的交付说明里写明理由。

| # | 事项 | 建议（默认按此执行） | 影响 |
|---|---|---|---|
| 5 | `pair/new` 是否加 `--qr` / Android 生成 QR | Linux 加 `--qr`（ASCII/PNG），Android 设置页也支持 | 配对 UX |
| 6 | QR 的 `fp`（SPKI pin）格式 | `sha256/<base64url(SPKI)>`；只在自签模式使用 | 自签部署安全 |
| 7 | 是否启用主密码作为可选第二把钥匙 | M3.3 可选（`POST /auth/password`） | 恢复能力 |
| 8 | 版本组合降级 | 若 AGP 9.4.1 × KSP 2.3.12 × Kotlin 2.4.21 组合失败：Kotlin 降到 2.3.21 / AGP 降到 8.x LTS | 构建 |
| 9 | `otpauth-migration://` 导入 | v1 不做，M3.3 评估 | 迁移体验 |
| 10 | 是否上 Play | v1 不上；自建 `/dl` | 分发/合规 |

---

## 附录 A：关键依据（官方文档 / 本地核对）

| # | 结论 | 依据 |
|---|---|---|
| A-1 | `KeyPairGenerator` 官方算法表只有 DH/DSA/EC/RSA/**XDH 33+**，**未列 Ed25519**；`KeyFactory` 同样未列 | <https://developer.android.com/reference/java/security/KeyPairGenerator>、<https://developer.android.com/reference/java/security/KeyFactory>（原文已落 `.tmp/scratch/kpg.md`、`.tmp/scratch/keyfactory.md`） |
| A-2 | `Signature` 的 Ed25519 自 **API 33**；`NamedParameterSpec.ED25519` 也是 33 | <https://developer.android.com/reference/java/security/Signature>、<https://developer.android.com/reference/java/security/spec/NamedParameterSpec> |
| A-3 | Android Keystore 文档未列 Ed25519；`KeyProperties` 无 `KEY_ALGORITHM_ED25519`；StrongBox 支持集：RSA 2048、AES 128/256、ECDSA/ECDH P-256、HMAC-SHA256 | <https://developer.android.com/privacy-and-security/keystore>、<https://developer.android.com/reference/android/security/keystore/KeyProperties> |
| A-4 | `setUserAuthenticationParameters` **API 30**，`timeout=0` 表示每次使用都认证，`allowedAuthenticators` 允许 `AUTH_DEVICE_CREDENTIAL`（文档未禁止 timeout=0 + device credential）；`setIsStrongBoxBacked` / `setUnlockedDeviceRequired` **API 28**；`setInvalidatedByBiometricEnrollment` **API 24**；`BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` 在 **API 28–29 的 `PromptInfo.build()` 会报错**；`CryptoObject` + device credential 仅在 **Android 11（API 30）及以上**支持 | <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>、<https://developer.android.com/reference/androidx/biometric/BiometricPrompt.PromptInfo.Builder>、<https://developer.android.com/reference/androidx/biometric/BiometricPrompt#authenticate(androidx.biometric.BiometricPrompt.PromptInfo,%20androidx.biometric.BiometricPrompt.CryptoObject)> |
| A-5 | ML Kit barcode：**bundled**（`com.google.mlkit:barcode-scanning:17.3.0`）静态链接、立即可用、约 **+2.4MB**、不依赖 Play services；**unbundled**（`play-services-mlkit-barcode-scanning`）需 Play services 下载、约 +200KB；两者 AAR `minSdkVersion=21` | <https://developers.google.com/ml-kit/vision/barcode-scanning/android> |
| A-6 | WorkManager **2.12.0** 的 minSdk 为 **24**（2.11 为 23） | <https://developer.android.com/jetpack/androidx/releases/work> |
| A-7 | Android **没有公开的** `javax.crypto.KDF` / `HKDFParameterSpec`（两个官方页 404） | `https://developer.android.com/reference/javax/crypto/KDF`（404） |
| A-8 | 16 KB 页：targetSdk **35+** 在 64 位设备上必须支持；Play 从 **2027-02-01** 起拒绝不支持者；NDK r28+ 默认对齐 | <https://developer.android.com/guide/practices/page-sizes> |
| A-9 | Play：**2026-08-31** 起新应用/更新必须 target **API 36**；存量需 ≥35，可申请延期至 2026-11-01 | <https://developer.android.com/google/play/requirements/target-sdk> |
| A-10 | Android 12+ 的 `allowBackup=false` 不足以阻止设备间迁移，需要 `dataExtractionRules` | <https://developer.android.com/about/versions/12/behavior-changes-12#backup-restore> |
| A-11 | `ClipDescription.EXTRA_IS_SENSITIVE`（API 33）用于隐藏剪贴板预览 | <https://developer.android.com/reference/android/content/ClipDescription#EXTRA_IS_SENSITIVE> |
| A-12 | BouncyCastle 类存在性（本地解包核对）：`Argon2BytesGenerator`、`Argon2Parameters(+Builder)`、`HKDFBytesGenerator`、`HKDFParameters`、`Ed25519PrivateKeyParameters`、`Ed25519PublicKeyParameters`、`Ed25519Signer` | `.tmp/scratch/jars/bcprov.jar`（`bcprov-jdk18on-1.86.jar`，7,224,011 B） |
| A-13 | 服务端 `rp_id` 必须 1..255 字节 | `server/internal/api/items.go:124` |
| A-14 | 现有配对码生成流程（code 32B、code_id 格式、blob 布局） | `linux/src/main.rs:343-380`；协议 §4.10 |
| A-15 | `/dl` 白名单来自 `<artifacts-dir>/SHA256SUMS`；产物名 `vkey-android.apk` | 协议 §4.12；`server/README.md:84-96`；`server/deploy/vkeyd.service`（`WorkingDirectory=.../data`） |
| A-16 | `setInvalidatedByBiometricEnrollment` 仅适用于「要求认证且未设置正数有效期」的密钥；设置正数有效期时不适用 | <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)> |

> 说明：A-1/A-2 的「文档未列」≠「实现一定不可用」。即便某些 API 33+ 设备
> `KeyPairGenerator.getInstance("Ed25519")` 能跑，我们仍按 **minSdk 26** 设计，
> 不能依赖它；用 BouncyCastle 是唯一跨版本确定的选择。

## 附录 B：版本清单（2026-10-27 核对）

| 组件 | 版本 | 来源 |
|---|---|---|
| AGP | 9.4.1 | Google Maven `com.android.tools.build:gradle` |
| Kotlin | 2.4.21（稳定） | Maven Central `kotlin-gradle-plugin` |
| KSP | 2.3.12（KSP2 独立版本线） | Maven Central |
| Compose BOM | 2026.09.00 | Google Maven |
| Room | 2.8.5 | Google Maven |
| WorkManager | 2.12.0 | Google Maven |
| androidx.biometric | 1.1.0（稳定；1.4.0-alpha07 为最新 alpha） | Google Maven |
| CameraX | 1.6.2 | Google Maven |
| ZXing core | 3.5.4 | Maven Central |
| OkHttp | 5.5.1 | Maven Central |
| kotlinx-serialization-json | 1.12.0 | Maven Central |
| kotlinx-coroutines | 1.11.0 | Maven Central |
| BouncyCastle | bcprov-jdk18on 1.86 | Maven Central |
| DataStore | 1.3.0 | Google Maven |
| SQLCipher（可选） | 4.19.1 | Maven Central |
| Signal argon2（备选） | 13.1 | Maven Central |

## 附录 C：拍板记录（2026-10-27）

| # | 拍板事项 | 结论 | 复核依据 |
|---|---|---|---|
| C-1 | 恢复码 | **强制**：抄写 + 回填校验为硬门禁（§5.5） | Keystore 失效即数据永久不可解（§2.2 冲突 3） |
| C-2 | `minSdk` | **26**（不再讨论 30） | §1.2 兼容性与 API 分支表 |
| C-3 | TOTP `rp_id` | 常量 **`"totp"`**，跨端同值（§3.6） | 协议 §4.6 不可变；TOTP 无 RP 语义 |
| C-4 | 设备管理 | **加** `GET /api/v1/devices`（§4.7）+ 协议 §4.9 吊销 | 设置页需要「列设备并吊销」 |

**已接受的架构性取舍（随本次拍板一并确认，不再讨论）：**

- Ed25519 私钥为**软件密钥**（Keystore 不支持 Ed25519）→ Keystore AES 包裹 + 生物识别门控（§2.2 冲突 1）；
- API 26–29 无强生物识别时降级为「设备凭据 + 正数有效期」弱模式，设置页必须标注（§2.3）；
- QR 载荷采用 §5.2（`fp` 为可选，仅自签模式）；
- 里程碑 3 个（M3.1 约 1.5 周 / M3.2 约 2 周 / M3.3 约 1 周，按 1 人估算）。

### 7.6 多用户开户接入（客户端）

- 入口仅在「设置」页的「用开户码接入」卡片；**启动不提示、不做引导页**（使用说明见 README）
- 手动输入开户码为主路径，扫码只是快捷方式（扫到 `ENROLL-` 文本回填）
- 流程：校验码格式 → 本地生成 32B `master_key` → `verifier = HKDF(master_key, username)` → 生成设备 Ed25519 密钥 →
  `POST /api/v1/auth/enroll` → **展示 52 位恢复码并要求勾选确认** → 写盘并读回校验 → 显示「已登录：<username>」
- 服务端只保存 `verifier`，**永不接触 `master_key`**
- 写盘采用 `VaultStore.writeAndVerify`：写入后读回比对 `master_key` 与 `device_id`，失败显式报错（不静默）
- 默认服务端地址为空：开源仓库不带任何作者域名，首次进入需用户自行填写（校验必须 `http://` 或 `https://` 开头）