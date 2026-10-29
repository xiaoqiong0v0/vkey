# vkey

自托管的双因素验证器 + 虚拟 FIDO2 安全密钥。数据端到端加密，服务端零知识。

Self-hosted 2FA authenticator and virtual FIDO2 security key. End-to-end encrypted; the server never sees your secrets.

## 组成

| 组件 | 说明 |
|---|---|
| `server/` | Go 服务端（`vkeyd`）：只存密文、设备签名鉴权、可选的 Pages 与产物下发 |
| `linux/` | Rust `vkey-hid`：通过 `/dev/uhid` 把一台 Linux 主机变成 FIDO2 安全密钥（浏览器里直接注册/登录） |
| `android/` | Android 客户端：本地 TOTP、扫码导入、密钥列表管理、条目同步 |
| `shared/` | 三端共用的协议文档与测试向量（**单一真源**） |

## 安全模型

```
master_key（仅客户端持有，不出设备）
  └── item_key = HKDF-SHA256(master_key, salt="vkey-item", info=item_id)
        └── ciphertext = AES-256-GCM(item_key, 条目明文)
```

- 服务端只保存 `ciphertext` / `nonce` 与必要元数据（`kind`、`rp_id`、版本、时间戳）
- 登录用 `verifier`（由 `master_key` 派生的不可逆值），不上传 `master_key`
- 每个请求由设备 Ed25519 私钥签名（方法 + URI + body 哈希 + 时间戳），服务端只存公钥
- **注意**：加密保护的是条目内容；元数据（你在哪些站点注册过）对服务端可见

## 快速开始

```bash
# 服务端
cd server && go build ./... && ./vkeyd init      # 初始化唯一用户
./vkeyd serve --addr 127.0.0.1:3150              # 前面挂反向代理（HTTPS）

# Linux 虚拟密钥
cd linux && cargo build --release
./target/release/vkey-hid init --server https://<你的域名>
./target/release/vkey-hid run                    # 浏览器里即可用 passkey

# Android
cd android && ./gradlew assembleDebug            # 或用项目主页/产物地址下载 APK
```

## 构建要求

- Go 1.22+、Rust 1.75+、JDK 17、Android SDK 35
- 工具链版本固定在 `mise.toml`（可选，用 [mise](https://mise.jdx.dev/) 自动切换）

## 开源与许可

**Apache License 2.0** —— 可自由用于个人与商业项目，含专利授权。

第三方依赖均为许可兼容的开源组件；Android 端使用 Google ML Kit（闭源但免费，仅用于扫码）。
发布前请自行确认各依赖的最新许可条款。

## 自建提示

- 服务端只监听回环地址，由反向代理终结 TLS
- 数据库文件本身未加密（条目载荷是密文，元数据明文）；备份请使用 `server/deploy/backup.sh`（GPG 加密）
- 恢复码/`master_key` 是唯一解密手段，丢失即不可恢复
