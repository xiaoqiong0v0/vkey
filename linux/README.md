# vkey-hid（Linux 客户端）

Rust 单 crate：`/dev/uhid` 虚拟 FIDO2 密钥 + vkeyd 零知识条目同步。
协议契约以 `shared/protocol.md` 为准；CTAP2 行为对齐 `spike/uhid_fido.py`
与 `docs/design.md` §8 的 10 条坑。

## 目录

```
linux/
├── Cargo.toml
├── src/
│   ├── main.rs                 # clap 子命令
│   ├── selftest.rs             # 无 uhid 自检
│   ├── config.rs               # 路径 / 0600 / 原子写
│   ├── crypto.rs               # HKDF/GCM/Argon2id/Ed25519/签名串/编码
│   ├── api.rs                  # HTTP 客户端
│   ├── store.rs                # 本地身份 + 条目密文缓存 + CTAP2 backend
│   ├── sync.rs                 # 增量拉取/推送 + LWW 冲突
│   ├── policy.rs               # 服务端策略（不可降级）
│   └── ctap2/
│       ├── cbor.rs             # CBOR 子集（true/false=0xF5/0xF4）
│       ├── hid.rs              # CTAPHID 分片/重组/CID/INIT/PING/CANCEL
│       ├── authenticator.rs    # GetInfo/MakeCredential/GetAssertion/Selection
│       └── uhid.rs             # /dev/uhid（Linux only）
├── packaging/
│   ├── 99-vkey-uhid.rules      # udev 放行 uhid/hidraw
│   └── vkey-hid.service        # systemd **user** unit
└── scripts/dev-sync-fedora.sh  # rsync + 远端 cargo test
```

## 构建

要求：Rust 1.75+（开发机实测 1.97.1）。

```bash
cd linux
cargo build --release
cargo test
```

Windows 上同样可以 `cargo build` / `cargo test`：`uhid` 模块用
`#[cfg(target_os = "linux")]` 隔离，Windows 下 `run` 会明确报错，其余命令
（login/pair/sync/status/selftest）可用。

## 安装（Linux）

```bash
# 1) 二进制
cargo install --path linux            # 或 sudo install -m755 target/release/vkey-hid /usr/local/bin/

# 2) udev：让普通用户打开 /dev/uhid 与虚拟 hidraw
sudo install -m644 linux/packaging/99-vkey-uhid.rules /etc/udev/rules.d/
sudo groupadd -f uhid
sudo usermod -aG uhid "$USER"
sudo udevadm control --reload-rules && sudo udevadm trigger
# 重新登录后生效

# 3) systemd user service
install -Dm644 linux/packaging/vkey-hid.service ~/.config/systemd/user/vkey-hid.service
systemctl --user daemon-reload
systemctl --user enable --now vkey-hid
journalctl --user -u vkey-hid -f
```

> 服务文件默认 `ExecStart=%h/.cargo/bin/vkey-hid run`；装到 `/usr/local/bin`
> 时改成对应路径。`Restart=on-failure` 已启用。
> 策略要求主密码时，`systemd-ask-password` 通过 user manager 的 agent 弹窗；
> 无图形会话时请先前台跑一次 `vkey-hid run`。

## 命令

```bash
# 首次接入（master_key 为 base32；省略 --master-key 则交互输入）
vkey-hid login --server https://vkey.example.com --master-key <BASE32>

# 生成一次性配对码（默认 10 分钟、单次可用）
vkey-hid pair-new

# 第二台设备接入
vkey-hid pair --server https://vkey.example.com --code XXXX-XXXX-...

# 手动同步 / 查看状态 / 自检
vkey-hid sync
vkey-hid status
vkey-hid selftest

# 设置 / 移除主密码（写入服务端 users.wrapped_key）
vkey-hid passwd
vkey-hid passwd --clear        # 需两次输入 yes 确认

# uhid daemon（前台；systemd 用）
vkey-hid run
```

数据目录：`$VKEY_DATA_DIR` → `$XDG_DATA_HOME/vkey` → `~/.local/share/vkey`
（Windows：`%LOCALAPPDATA%\vkey`）。文件均为 `0600`：

| 文件 | 内容 |
|---|---|
| `local.key` | 32B 随机 KEK（无主密码场景包裹 master_key） |
| `identity.json` | server_url / device_id / device_name / ed25519_seed / token / wrapped_master_key / pw_salt? / username |
| `items.json` | 条目缓存，**只存密文**（`ct`+`nonce`），私钥不落明文 |
| `seq` | 上次同步到的服务端 version |
| `policy.json` | 上次服务端策略（仅服务端不可达时回退） |
| `conflicts/*.conflict-<ts>.json` | LWW 冲突落败副本（密文，可恢复） |

## 主密码策略

- 每次 `run` / `sync` / `selftest` 先 `GET /api/v1/policy`，并按三条分支执行：
  1. `require_master_pw_enforced=true`：必须输入主密码，`Argon2id(pw, pw_salt, 65536/3/1)`
     解包 `wrapped_key`；拿不到包裹或密码错误即**硬失败**，不回退 `local.key`。
  2. `require_master_pw=true` 但 `enforced=false`：服务端没有密码包裹，明确报错并提示
     先执行 `vkey-hid passwd`，**不静默放行**。
  3. `false`：用 `local.key` 解包，无需交互。
- 服务端不可达：使用 `policy.json` 缓存（含 `require_master_pw_enforced`）；
  **无缓存则失败关闭**。
- 服务端可达时以服务端为准（协议 §4.1：缓存不得覆盖服务端策略）。

### 主密码包裹的写入与移除

`vkey-hid passwd` 用新密码包裹 master_key（`nonce(12)||ct||tag`）并
`POST /api/v1/auth/password` 写入服务端 `users.wrapped_key` / `users.pw_salt`；
其它设备可通过 `auth/token` 或 `pair/claim` 取得同一份包裹。
`vkey-hid passwd --clear` 需两次输入 `yes`，随后 `DELETE /api/v1/auth/password`
清空服务端两列（防止误删导致无 `local.key` 的设备永久无法解密）。

## 测试

```bash
cd linux
cargo test
```

- `tests/vectors.rs`：`shared/vectors/*.json` 逐字节比对（KDF/AEAD/signing/encoding）。
- `src/ctap2/*` 单测：CBOR、CTAPHID 7609B、INIT 唯一 CID、CONT 错序、CANCEL、
  MakeCredential/GetAssertion/DER 验签、allowList/rp_id 匹配。
- `tests/policy.rs`：主密码三分支（enforced / require 未 enforced / false）与
  「服务端不可达不可放宽」。
- `tests/e2e.rs`：自动 `go build ./cmd/vkeyd` → 临时 db（`.tmp/scratch/`）
  → login → 写 TOTP → selftest → pair-new → 第二设备 pair/sync → 解密/验签；
  另有主密码全流程（写入包裹 → 重启后需密码 → 错密码拒绝 → 对密码通过 → 清除）。

## Fedora 测试机

机器（192.168.1.108）恢复后：

```bash
chmod +x linux/scripts/dev-sync-fedora.sh
VKEY_FEDORA_HOST=afubek@192.168.1.108 VKEY_FEDORA_DIR=~/proj/vkey \
  linux/scripts/dev-sync-fedora.sh
```

脚本会 rsync `linux/` 与 `shared/`，并在远端跑 `cargo test --release`。
随后在 Fedora 上按上面「安装」步骤跑 udev + user service，用 Chromium
做真实 register/auth（`selftest` 不经过 uhid，不能替代浏览器验收）。

## 排障

| 现象 | 检查 |
|---|---|
| `打开 /dev/uhid 失败: Permission denied` | udev 规则 / `uhid` 组 / 重新登录 |
| 浏览器停在「插入安全密钥」 | `journalctl --user -u vkey-hid`；确认 `Virtual FIDO2 Key` hidraw 存在；确认 GetInfo 无 clientPin |
| `require_master_pw=true` 但本地无包裹 | 在已登录设备执行 `vkey-hid passwd`；或重新 `login/pair` 取得包裹 |
| `服务端策略要求主密码，但服务端未存密码包裹` | 执行 `vkey-hid passwd` 写入 `wrapped_key` |
| `服务端不可达且本地没有策略缓存` | 先联网跑一次 `status` 建立缓存 |
| `ts_skew` | 本机时钟误差需在 ±120s 内 |
| 配对码 `code_used`/`code_expired` | 重新 `pair-new`（10 分钟、单次） |

## 并发契约

（项目 `docs/ASYNC.md` 由服务端维护；本客户端不改 `docs/`，在此登记。）

- `LocalStore` 由 `Arc<Mutex<LocalStore>>` 保护；uhid 主线程与同步线程共享。
- 网络请求在锁外执行；锁内只做 dirty 快照、结果应用与落盘。
- 后台同步线程：`recv_timeout(30s)` 或收到 `SyncTrigger`（凭据新增/签名后）
  唤醒；错误只打印日志，不退出 daemon。
- uhid 主循环单线程阻塞读 `/dev/uhid`；SIGINT/SIGTERM 通过 `EINTR` +
  `AtomicBool` 退出并发送 `UHID_DESTROY`。
- 签名私钥仅在 `get_assertion` 瞬间从条目明文导入 `SigningKey`，签名后
  随 `Zeroizing` / `SigningKey` 的 Drop 清零；master_key 全程 `Zeroizing`。
