# vkeyd — vkey 服务端（M1）

vkey 的零知识同步服务端：只保存 verifier、设备公钥与**条目密文**，永远不持有
`master_key`、主密码或任何明文。协议契约见 [`../shared/protocol.md`](../shared/protocol.md)。

- 语言/驱动：Go 1.27.3 + 纯 Go sqlite（`modernc.org/sqlite`，无 CGO）
- 形态：单二进制；TLS 由 nginx 终止，本进程只监听回环
- 范围：条目同步、设备认证、扫码配对、引导脚本、主页（唯一入口，含 APK 下载）；
  用户模式 `single`（默认，单账号）/ `admin`（多用户，仅 CLI 开户，见下）
- 错误响应 `message` 按请求头 `Accept-Language` 返回中文/英文，`code` 语言无关

## 目录

```
server/
├── cmd/
│   ├── vkeyd/          # 服务端 CLI（init / serve / policy set / update / user / purge）
│   └── genvectors/     # 重新生成 shared/vectors/*.json
├── internal/
│   ├── api/            # 路由、鉴权中间件、handlers、页面、限流
│   ├── crypto/         # HKDF / AEAD / Argon2id / 签名串 / 编码
│   ├── pair/           # 配对码生成、规范化、blob 封装
│   ├── policy/         # 协议常量与策略视图
│   ├── store/          # sqlite 持久层（含 LWW 与 seq）
│   └── version/        # 版本号
├── deploy/             # systemd unit、nginx 配置、部署脚本
├── ASYNC.md            # 并发契约（必读）
└── README.md
```

## 本地开发

```bash
cd server

# 建库（stdout 只打印一次 master_key，务必离线保存）
go run ./cmd/vkeyd init --db ../.tmp/scratch/vkey.db

# 启动（只监听本机；生产由 nginx 反代，端口与生产保持一致用 3150）
go run ./cmd/vkeyd serve --db ../.tmp/scratch/vkey.db --listen 127.0.0.1:3150 \
  --domain <YOUR_DOMAIN>

# 改策略（主密码 / 用户模式 / 每用户配额，-1 表示不限制）
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --require-master-pw=true
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --user-mode=admin --max-items-per-user=2000
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --max-bytes-per-user=50MiB --max-devices-per-user=20

# 清理墓碑（终端里不带开关 = 交互式勾选：空格选择、回车列出、y 删除）
go run ./cmd/vkeyd purge --db ../.tmp/scratch/vkey.db

# 只列清单，不写库
go run ./cmd/vkeyd purge --db ../.tmp/scratch/vkey.db --dry-run

# 不交互，直接删除全部墓碑（仅控制台/运维手动）
go run ./cmd/vkeyd purge --db ../.tmp/scratch/vkey.db --yes
```

`init` 的行为：

- `--master-key` 缺省时生成 32B 随机值；
- stdout **只有一行** `master_key: <base32 无填充>`，其余信息走 stderr；
- 重复 init 返回非 0（避免覆盖已有库）。

## 多用户（admin 模式）

`user_mode` 存库（meta 键 `user_mode`），默认 `single`（行为与 M1 一致，无 HTTP 注册）。
切到 `admin` 后由管理员 CLI 开户，**没有自助注册接口**；客户端凭一次性开户码调用
`POST /api/v1/auth/enroll`（`master_key` 在客户端本地生成，服务端只收 `verifier`，
零知识边界不变）。机制细节见仓库根 `docs/design.md` §4.4。

```bash
# 1) 切换到 admin 模式
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --user-mode=admin

# 2) 开户：签发一次性开户码（默认 30 分钟；stdout 为固定 key=value 五行）
go run ./cmd/vkeyd user add alice --db ../.tmp/scratch/vkey.db --domain vkey.example.com
#   username=alice
#   code=ENROLL-XXXX-XXXX
#   code_id=<可撤销用的 id>
#   expires_at=<unix 秒>
#   join_url=https://vkey.example.com/join?c=ENROLL-XXXX-XXXX   ← 可直接发给对方的开户链接
# 不带 --domain 时 join_url 为相对路径 /join?c=…（stderr 提示补全域名）

# 3) 客户端凭码绑定（verifier=HKDF(master_key,"alice")，本地算）：
curl -X POST https://<server>/api/v1/auth/enroll -H 'Content-Type: application/json' \
  -d '{"code":"ENROLL-XXXX-XXXX","username":"alice","verifier":"<base64url(32B)>",
       "device":{"name":"pixel","platform":"android","pubkey":"<base64url(32B)>"}}'
# → 200 {"device_id","token","user_id","username"}；token 与 /auth/token 同语义
# 错误：invalid_code / code_expired(410) / username_taken(409) / invalid_verifier；限流 60/min/IP

# 4) 账号管理
go run ./cmd/vkeyd user list --db ../.tmp/scratch/vkey.db            # 账号 + 待用开户码
go run ./cmd/vkeyd user revoke <code_id> --db ../.tmp/scratch/vkey.db # 撤销未用开户码
go run ./cmd/vkeyd user disable alice --db ../.tmp/scratch/vkey.db    # 全部设备立即 401，数据保留
go run ./cmd/vkeyd user enable --id <user_id> --db ../.tmp/scratch/vkey.db
go run ./cmd/vkeyd user delete alice --db ../.tmp/scratch/vkey.db     # 不带 --yes：只打印将删除的行数
go run ./cmd/vkeyd user delete alice --db ../.tmp/scratch/vkey.db --yes  # 二次确认：级联删除

# 5) 每用户配额（默认 items=1000 / bytes=20MiB / devices=10；-1 不限制）
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --max-items-per-user=500
```

超限响应统一 `409` + `error.code ∈ {quota_items, quota_bytes, quota_devices}`；
条目超限整批回滚。日志只记 user_id/username/结果码，绝不记 code/verifier/token。

## Android 更新信息（`GET /api/v1/update/android`）

客户端启动时拉这个免鉴权端点决定是否提示升级（契约见 `../shared/protocol.md` §4.14）：

- **未配置完整**（`version_code` 与 `sha256` 缺任一项）→ `204` 无正文，客户端视为「暂无更新」；
- **配置完整** → `200` + `Cache-Control: public, max-age=300`；
- 服务端**只读库、不访问 GitHub API**，`url` 由配置拼接：

| `--update-source` | `url` |
|---|---|
| `github`（缺省） | `https://github.com/<repo>/releases/latest/download/<asset>` |
| `local` | `<server_url>/dl/<asset>`（白名单仍由产物目录的 `SHA256SUMS` 决定） |

缺省值：`source=github`、`repo=xiaoqiong0v0/vkey`、`asset=vkey-android.apk`。

```bash
# 查看当前配置（stdout 为固定 key=value 行；configured=false ⇒ 客户端看到 204）
go run ./cmd/vkeyd update show --db ../.tmp/scratch/vkey.db

# 单项修改：各项独立，未给出的保持不变
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --update-source=github
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --update-repo=xiaoqiong0v0/vkey --update-asset=vkey-android.apk

# 发布新版本：写 version_code 与 sha256（两者同时写入才生效，并刷新 published_at）
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db \
  --update-version-code=30101 --update-version-name=0.3.2 \
  --update-sha256=<APK 的 64 位 hex> --update-size=<APK 字节数> --update-notes='修复 xxx'
```

`--update-sha256` 必须是 64 位十六进制（CLI 统一转小写），`--update-repo` 必须是 `owner/repo`，
`--update-asset` 必须是单段文件名（字母数字与 `. _ -`）；校验失败的非 0 退出并保留已写入的项。

### 发布新版本时的操作清单

1. 本地构建 APK（`android/`），确认 `versionCode` / `versionName` 已递增。
2. 算摘要与体积：
   ```bash
   sha256sum vkey-android.apk                 # Windows: Get-FileHash -Algorithm SHA256 vkey-android.apk
   stat -c %s vkey-android.apk                # Windows: (Get-Item vkey-android.apk).Length
   ```
3. 发布 GitHub Release（tag `vX.Y.Z`）：把 APK 作为资产上传，**文件名必须等于 `--update-asset`**
   （默认 `vkey-android.apk`）——`releases/latest/download/<asset>` 靠它命中，文件名不符则客户端 404。
   改走自托管时：把 APK 放进 `--artifacts-dir` 并更新同目录 `SHA256SUMS`，再把 `--update-source` 设为 `local`。
4. 在服务端库上写配置（`version_code` 与 `sha256` 必须同一条命令或先后都写入，缺一项仍是 204）：
   ```bash
   ~/work/vkey/bin/vkeyd policy set --db ~/work/vkey/data/vkeyd.db \
     --update-version-code=<n> --update-version-name=<x.y.z> \
     --update-sha256=<APK sha256> --update-size=<字节数> --update-notes='<说明>'
   ```
5. 自检：
   ```bash
   ~/work/vkey/bin/vkeyd update show --db ~/work/vkey/data/vkeyd.db   # configured=true
   curl -fsS https://<YOUR_DOMAIN>/api/v1/update/android             # 200 + 正确 url/sha256/version_code
   ```
   响应缓存 5 分钟（`max-age=300`），改完配置最多 5 分钟后客户端才看到新值。
6. 回滚：把 `--update-version-code` / `--update-sha256` 改回旧值。注意 `releases/latest/download/`
   永远指向最新 Release，旧 APK 已不在其中时需把旧资产补挂到新 Release，或改用 `local` 源。

## 测试

```bash
cd server
go build ./... && go vet ./... && go test ./...
```

测试覆盖（详见 `ASYNC.md` 与 `../shared/protocol.md` §9）：

- `internal/crypto`：与 `shared/vectors/*.json` 逐字节比对（KDF / AEAD / verifier /
  pair KEK / 签名串 / 编码），以及错误路径；
- `internal/api`：签名鉴权、时钟偏移、篡改 body、token 轮换/吊销、LWW 三分支、
  8 KiB 上限、墓碑、配对单次可用/过期/二次使用、端到端同步 + 解密。

重新生成测试向量（仅在协议变更时执行）：

```bash
cd server
go run ./cmd/genvectors            # 写入 ../shared/vectors
```

测试用固定输入生成，输出可复现；实现本身始终使用随机 nonce。

## 交叉编译与发布产物

```bash
cd server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" ./cmd/vkeyd
```

ARM64 把 `GOARCH` 换成 `arm64`。`CGO_ENABLED=0` 是必须的（`modernc.org/sqlite` 为纯 Go，
开启 CGO 反而会引入 glibc 依赖，破坏可移植性）。产物部署到 `~/work/vkey/bin/vkeyd`。

### 客户端产物分发（`/dl/*`）

`vkeyd serve --artifacts-dir <dir>`（默认 `./artifacts`）把该目录作为**只读**产物源：
`GET /dl/{name}` 只放行 `<dir>/SHA256SUMS` 里列出的文件名（名字须匹配 `^[A-Za-z0-9._-]+$`），
`GET /dl/SHA256SUMS` 返回清单本身；目录不存在时只有 `/dl/*` 返回 404，其它接口不受影响。

Linux 产物由 `linux/scripts/build-artifacts.sh` 在 Linux 上构建（本机不执行）：

```bash
bash linux/scripts/build-artifacts.sh     # 产出 dist/vkey-hid-linux-<arch>.tar.gz + dist/SHA256SUMS
```

把 `dist/` 整体同步到服务端的 `artifacts/` 目录后，`/install.sh` 会按 `SHA256SUMS` 校验并安装。


## 部署（ECS）

目标与实际部署一致——主机 `<SSH_USER>@<SERVER_IP>`，域名 `<YOUR_DOMAIN>`，
vkeyd 只监听 `127.0.0.1:3150`，TLS 由 nginx 终止（实测 nginx/1.18.0）：

```
/home/ecs-user/work/vkey/
├── bin/vkeyd          # 二进制（systemd 的 ExecStart）
└── data/vkeyd.db      # sqlite 库（含 -wal/-shm；ReadWritePaths 只放开这个目录）
/etc/systemd/system/vkeyd.service
/etc/nginx/sites-available/<YOUR_DOMAIN>.conf
/etc/nginx/sites-enabled/<YOUR_DOMAIN>.conf -> ../sites-available/...
```

端口用 **3150**：本机 8080 已被其它服务（docker-proxy）占用。站点配置放
`sites-available` + `sites-enabled` 软链，**不要**再往 `conf.d/` 放一份，否则会被加载两次。

### 首次部署：两阶段上线（顺序不能反）

443 块要求证书已存在，否则 `nginx -t` 直接失败，所以先只上 80 块去取证书。

1. 建目录、上传二进制并建库（**master_key 只显示一次**，立即存进离线密码管理器）：

   ```bash
   ssh <SSH_USER>@<SERVER_IP> 'mkdir -p ~/work/vkey/bin ~/work/vkey/data'
   scp .tmp/scratch/vkeyd-linux-amd64 <SSH_USER>@<SERVER_IP>:~/work/vkey/bin/vkeyd
   ssh -t <SSH_USER>@<SERVER_IP> 'chmod 755 ~/work/vkey/bin/vkeyd \
     && cd ~/work/vkey/data && ../bin/vkeyd init --db ~/work/vkey/data/vkeyd.db'
   ```

   服务端没有恢复手段；库 + 任一台已配对设备才能恢复。

2. 安装 systemd unit 与 nginx 配置（阶段 1：先把 443 块注释掉，只启用 80 块）：

   ```bash
   scp server/deploy/vkeyd.service <SSH_USER>@<SERVER_IP>:/tmp/vkeyd.service
   scp server/deploy/nginx-vkey.conf <SSH_USER>@<SERVER_IP>:/tmp/vkey-nginx.conf
   ssh -t <SSH_USER>@<SERVER_IP> 'sudo install -m 0644 /tmp/vkeyd.service /etc/systemd/system/vkeyd.service \
     && sudo install -m 0644 /tmp/vkey-nginx.conf /etc/nginx/sites-available/<YOUR_DOMAIN>.conf \
     && sudo ln -sfn /etc/nginx/sites-available/<YOUR_DOMAIN>.conf \
        /etc/nginx/sites-enabled/<YOUR_DOMAIN>.conf \
     && sudo systemctl daemon-reload && sudo systemctl enable --now vkeyd \
     && sudo nginx -t && sudo systemctl reload nginx'
   ```

3. 阶段 2：申请证书（ACME webroot 是 `/var/www/html`），再放开 443 块并 reload：

   ```bash
   sudo certbot certonly --webroot -w /var/www/html -d <YOUR_DOMAIN>
   # 取消 443 块注释后：
   sudo nginx -t && sudo systemctl reload nginx
   ```

   续期：`sudo certbot renew --dry-run` 验证；webroot 路径不变，续期后 `systemctl reload nginx`。

4. 自检：

   ```bash
   curl -fsS https://<YOUR_DOMAIN>/api/v1/health
   curl -fsS https://<YOUR_DOMAIN>/api/v1/policy
   ```

## 日常更新

```bash
./server/deploy/deploy.sh            # dry-run（默认）：只打印计划，退出码 1
./server/deploy/deploy.sh --apply    # 真执行
```

`--apply` 的顺序：编译 → 上传二进制到 `bin/vkeyd.new` → 安装 nginx 配置并 `nginx -t`
（**失败即用 `/etc/nginx/backup-<时间戳>/` 的备份回滚并退出，不 reload、不重启**）→
安装 unit → 旧二进制留作 `vkeyd.prev` 后替换并 `systemctl restart vkeyd` →
`systemctl reload nginx` → 健康检查。证书缺失时脚本会跳过 nginx 配置安装并提示
先走上面的两阶段流程。**仓库与 CI 不会自动部署。**

## 运维与安全注意

- **只监听回环**：`--listen 127.0.0.1:3150`，公网入口必须是 nginx；直连暴露会让
  下面的限流键变成可伪造值。
- **限流键与 `X-Forwarded-For`**：vkeyd 取 XFF **首项**做限流键（`internal/api/api.go`
  的 `clientIP`），所以 nginx 必须写 `proxy_set_header X-Forwarded-For $remote_addr;`
  ——用 `$proxy_add_x_forwarded_for` 会保留客户端自带值，换伪造 IP 即可绕过限流。
- **备份**：`vkey.db`（连同 `-wal`/`-shm`）需要定期备份；服务端没有 master_key，
  所以「库 + 任一台已配对设备」即可恢复，单独拿到库无法解密。
- **主密码策略**默认 `false`；`require_master_pw=true` 只影响客户端行为，
  服务端仍然无法解密任何数据。
- **审计表**只记录元数据（动作、设备、时间），不含明文/密文。
- `GET /`（唯一入口：状态 + 手机配置二维码/深链 + Android APK + Linux 安装命令）、`/install.sh`、
  `/install.ps1` 均为纯展示/模板，不含解密逻辑；`GET /pair` 仅 301 跳转到 `/`（保留老链接）；
  `/pair/qr.png` 只编码 `vkey://config?server=<地址>`（仅地址，无配对码/主密钥）；
  `/dl/*` 只做白名单静态分发（白名单来自产物目录的 `SHA256SUMS`）。
- **开户落地页 `/join`**：`GET /join?c=<开户码>` 与 `GET /join/qr.png?c=<开户码>` 仅在
  `user_mode=admin` 且码有效未用时返回 200，其余情况统一 4xx + 同一文案「链接无效或已过期」
  （不区分不存在/已用/过期，防枚举）。开户码在 query 里，属一次性凭据：
  **访问日志对 `/join*` 只记路径、不记 query**（`internal/api/api.go` 的 `safeURI`），
  页面/二维码只含地址与开户码，绝无 master_key/token；响应头 `Cache-Control: no-store`。
  打开页面**不消费**开户码（只读 `PeekEnrollCode`），消费仍只在 `POST /api/v1/auth/enroll`。
- 速率限制为进程内固定窗口（60 次/分钟/IP，作用于 `auth/token` 与 `pair/claim`），
  重启清零；多实例部署需上移到 nginx。

## 数据删除策略

- **客户端删除 = 逻辑删除（墓碑）**：客户端删除条目时只是写入
  `deleted_at != 0` 的新版本，服务端**永不**因客户端请求物理删除行。
  墓碑是同步协议的一部分（其它设备靠它得知删除），`GET /items` 会照常下发。
- **物理删除只有一条通道**：`vkeyd purge --db <path>`
  —— 在服务器控制台由运维手动执行。**没有、也不会提供任何 HTTP 删除接口**
  （例如 `DELETE /api/v1/items` 之类一律不实现）。
- 命令行为：

  ```bash
  vkeyd purge --db <path>            # 终端里：交互勾选后删除；没有终端：只列清单
  vkeyd purge --db <path> --dry-run  # 只列清单（显式写法），不写库
  vkeyd purge --db <path> --yes      # 不交互，直接删除全部墓碑
  ```

  - **交互式选择**（无 `--yes`/`--dry-run`，且 stdin 是终端）：
    - 列表每行是 `id前缀 kind rp_id deleted_at version`，光标行以 `> ` 标示，
      勾选标记 `[x]` / 未勾选 `[ ]`；
    - 按键：`↑`/`↓`（或 `k`/`j`）移动、`空格` 勾选/取消、`a` 全选/全不选、
      `回车` 结束选择；`Ctrl+C` 中断（不写库）。
    - 结束选择后再次列出**已勾选**条目摘要，并提示 `删除以上 N 条？(y/N)`：
      输入 `y`（大小写不敏感）才在单事务内删除并打印「已物理删除 N 条」；
      其它输入打印「已取消，未做任何修改」；一条都没勾选则打印「未选择任何条目」。
      取消与中断都以 0 退出。
  - **非交互**（管道/重定向，或显式 `--dry-run`）：只列清单并提示
    「当前没有终端，无法交互；确认后用 --yes」，不写库。
  - **远端服务器必须 `ssh -t`**：`ssh host 'cmd'` 不分配终端，会退化为只列清单；
    要交互就得申请 TTY：

    ```bash
    ssh -t <SSH_USER>@host 'cd ~/work/vkey && sudo -n ./bin/vkeyd purge --db ./data/vkeyd.db'
    ```

  - 只影响 `items` 表中 `deleted_at IS NOT NULL AND deleted_at != 0` 的行；
    无墓碑时打印「没有已逻辑删除的条目」并以 0 退出。
  - `--dry-run` 与 `--yes` 同时给出时以 `--dry-run` 为准（更安全），并在 stderr 提示。
  - 防御断言：删除在单事务内执行，只有「实际影响行数 == 事务内统计的墓碑数」
    且「删除前后非墓碑行数完全一致」才提交，否则回滚并报错退出；
    交互式按勾选删除时，额外要求「实际影响行数 == 勾选条数」（勾选项已不是墓碑即回滚）。
- **范围**：本策略只覆盖 `items`。`item_conflicts` / `pairs` / `audit`
  等表的清理不在本次范围内（需要时另行设计，且同样只走控制台）。

## M1 已知边界

- 仅单账号（`users` 表可容纳多行，但 CLI 与策略只操作最早创建的账号）。
- 无 TLS/ACME 内置实现（由 nginx + certbot 承担）。
- 无 APK/MSI 构建（Linux 的 `.tar.gz` 由 `linux/scripts/build-artifacts.sh` 产出）。
- 冲突副本 `item_conflicts` 只落库，暂无查询 API（运维可直接查 sqlite）。
- sqlite 单连接串行；详见 `ASYNC.md` 的边界说明。

## Android 更新信息的惰性刷新

服务端**不主动轮询** GitHub；只在客户端请求 `GET /api/v1/update/android` 且距上次检查超过 TTL 时，
同步拉取一次 `https://github.com/<repo>/releases/latest/download/android.json`（5s 超时）。

```bash
# 默认开启，间隔 24 小时
vkeyd policy set --db ./data/vkeyd.db --update-auto-check=true --update-check-interval=86400

# 完全关闭（只用 CLI 静态写入的版本信息）
vkeyd policy set --db ./data/vkeyd.db --update-auto-check=false

# 查看当前状态（含 last_checked_at / last_check_error）
vkeyd update show --db ./data/vkeyd.db
```

- 成功才覆盖缓存；失败保留旧值并记 `last_check_error`，接口仍返回 200/204
- 同一时刻只允许一次拉取，并发请求用缓存返回
- `android.json` 由 Release 工作流自动生成并上传（含 `version_code`/`sha256`/`size`）