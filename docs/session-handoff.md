# 会话交接（2026-10-26，写后冻结）

## 本次会话产出

| 产出 | 位置 |
|---|---|
| Ente Auth 服务端（生产，已上线） | `ecs-user@47.97.78.223:~/work/ente/`，域名 `ente.xiaoqiong0v0.cn` |
| git 服务（cgit + git-http-backend） | 同机 `~/work/git/`，`https://git.xiaoqiong0v0.cn` |
| 虚拟 FIDO2 密钥 spike（**已跑通 register+auth**） | `D:\WorkSpace\my_open\vkey\spike\` |
| 新项目方案 | `D:\WorkSpace\my_open\vkey\docs\design.md` |
| 一手证据 | `D:\WorkSpace\my_open\vkey\docs\evidence\` |

## 已冻结的决定（新会话勿再讨论）

1. 不做 H5/网页端（不在浏览器解密/显示 TOTP）；服务端只保留 `/pair`、`/install.sh|ps1`、`/` 自检页
2. 不 fork 2FAS（其 WebAuthn 支持为 0，Pass 是 BUSL）；不依赖 hybrid 扫码（中转在 Google）
3. Linux 主路径 = uhid 虚拟 FIDO2；Windows 主路径 = 官方 WebAuthn Plugin API（Win11 24H2+）；扩展只做兜底
4. Android 第一版只做 TOTP，不做 CredentialProviderService
5. 服务端不做「动态生成安装包」，改为「引导脚本 + 通用产物」

## 待决定（开工前）

- 项目名是否用 `vkey`
- 服务端语言（建议 Go 单二进制）
- 第一版范围是否「服务端 + Linux」先闭环
- 本目录**尚未 `git init`**（待确认后初始化并首次提交 design/evidence/spike）

## 环境状态（Fedora 测试机 192.168.1.108）

- SSH：本机已加公钥（`opencode-ssh-test`），`ssh afubek@192.168.1.108` 免密可用
- 浏览器：Fedora 44 / Chromium 156（RPM，非 Flatpak）/ Firefox
- uhid daemon：`/home/afubek/proj/uhid-fido/spike/uhid_fido.py`，用 `sudo -n bash <spike>/restart.sh` 重启
  - **凭据仅内存**，重启即丢（spike 限制）
  - 需要 `python3-cryptography`、`python3-websockets`（已装）
- 自动化测试：`probe_matrix.py`（无头 Chrome + CDP，无需人工点击）

## CTAP2 实现硬约束（10 条，务必照做）

见 `docs/design.md` §8；每条都来自实测或 Chromium 源码（证据在 `docs/evidence/`）。

## 未完成/遗留

- `rk:true` + residentKey 时 Chrome 静默等待（UV 语义未解）→ 第一版不声明 rk，只做非可发现凭据
- Windows Plugin API 仅依据头文件，未实测
- 国产 ROM Credential Manager 可用性未实测
