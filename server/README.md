# vkeyd — vkey 服务端（M1）

vkey 的零知识同步服务端：只保存 verifier、设备公钥与**条目密文**，永远不持有
`master_key`、主密码或任何明文。协议契约见 [`../shared/protocol.md`](../shared/protocol.md)。

- 语言/驱动：Go 1.27.3 + 纯 Go sqlite（`modernc.org/sqlite`，无 CGO）
- 形态：单二进制；TLS 由 nginx 终止，本进程只监听回环
- 范围：单账号、条目同步、设备认证、扫码配对、引导脚本、主页（唯一入口，含 APK 下载）

## 目录

```
server/
├── cmd/
│   ├── vkeyd/          # 服务端 CLI（init / serve / policy set / purge）
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
  --domain vkey.xiaoqiong0v0.cn

# 改策略
go run ./cmd/vkeyd policy set --db ../.tmp/scratch/vkey.db --require-master-pw=true

# 查看将被物理删除的墓碑（默认即 dry-run，不写库）
go run ./cmd/vkeyd purge --db ../.tmp/scratch/vkey.db

# 真正执行物理删除（仅控制台/运维手动）
go run ./cmd/vkeyd purge --db ../.tmp/scratch/vkey.db --yes
```

`init` 的行为：

- `--master-key` 缺省时生成 32B 随机值；
- stdout **只有一行** `master_key: <base32 无填充>`，其余信息走 stderr；
- 重复 init 返回非 0（避免覆盖已有库）。

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

目标与实际部署一致——主机 `ecs-user@47.97.78.223`，域名 `vkey.xiaoqiong0v0.cn`，
vkeyd 只监听 `127.0.0.1:3150`，TLS 由 nginx 终止（实测 nginx/1.18.0）：

```
/home/ecs-user/work/vkey/
├── bin/vkeyd          # 二进制（systemd 的 ExecStart）
└── data/vkeyd.db      # sqlite 库（含 -wal/-shm；ReadWritePaths 只放开这个目录）
/etc/systemd/system/vkeyd.service
/etc/nginx/sites-available/vkey.xiaoqiong0v0.cn.conf
/etc/nginx/sites-enabled/vkey.xiaoqiong0v0.cn.conf -> ../sites-available/...
```

端口用 **3150**：本机 8080 已被其它服务（docker-proxy）占用。站点配置放
`sites-available` + `sites-enabled` 软链，**不要**再往 `conf.d/` 放一份，否则会被加载两次。

### 首次部署：两阶段上线（顺序不能反）

443 块要求证书已存在，否则 `nginx -t` 直接失败，所以先只上 80 块去取证书。

1. 建目录、上传二进制并建库（**master_key 只显示一次**，立即存进离线密码管理器）：

   ```bash
   ssh ecs-user@47.97.78.223 'mkdir -p ~/work/vkey/bin ~/work/vkey/data'
   scp .tmp/scratch/vkeyd-linux-amd64 ecs-user@47.97.78.223:~/work/vkey/bin/vkeyd
   ssh -t ecs-user@47.97.78.223 'chmod 755 ~/work/vkey/bin/vkeyd \
     && cd ~/work/vkey/data && ../bin/vkeyd init --db ~/work/vkey/data/vkeyd.db'
   ```

   服务端没有恢复手段；库 + 任一台已配对设备才能恢复。

2. 安装 systemd unit 与 nginx 配置（阶段 1：先把 443 块注释掉，只启用 80 块）：

   ```bash
   scp server/deploy/vkeyd.service ecs-user@47.97.78.223:/tmp/vkeyd.service
   scp server/deploy/nginx-vkey.conf ecs-user@47.97.78.223:/tmp/vkey-nginx.conf
   ssh -t ecs-user@47.97.78.223 'sudo install -m 0644 /tmp/vkeyd.service /etc/systemd/system/vkeyd.service \
     && sudo install -m 0644 /tmp/vkey-nginx.conf /etc/nginx/sites-available/vkey.xiaoqiong0v0.cn.conf \
     && sudo ln -sfn /etc/nginx/sites-available/vkey.xiaoqiong0v0.cn.conf \
        /etc/nginx/sites-enabled/vkey.xiaoqiong0v0.cn.conf \
     && sudo systemctl daemon-reload && sudo systemctl enable --now vkeyd \
     && sudo nginx -t && sudo systemctl reload nginx'
   ```

3. 阶段 2：申请证书（ACME webroot 是 `/var/www/html`），再放开 443 块并 reload：

   ```bash
   sudo certbot certonly --webroot -w /var/www/html -d vkey.xiaoqiong0v0.cn
   # 取消 443 块注释后：
   sudo nginx -t && sudo systemctl reload nginx
   ```

   续期：`sudo certbot renew --dry-run` 验证；webroot 路径不变，续期后 `systemctl reload nginx`。

4. 自检：

   ```bash
   curl -fsS https://vkey.xiaoqiong0v0.cn/api/v1/health
   curl -fsS https://vkey.xiaoqiong0v0.cn/api/v1/policy
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
- 速率限制为进程内固定窗口（60 次/分钟/IP，作用于 `auth/token` 与 `pair/claim`），
  重启清零；多实例部署需上移到 nginx。

## 数据删除策略

- **客户端删除 = 逻辑删除（墓碑）**：客户端删除条目时只是写入
  `deleted_at != 0` 的新版本，服务端**永不**因客户端请求物理删除行。
  墓碑是同步协议的一部分（其它设备靠它得知删除），`GET /items` 会照常下发。
- **物理删除只有一条通道**：`vkeyd purge --db <path> --yes`
  —— 在服务器控制台由运维手动执行。**没有、也不会提供任何 HTTP 删除接口**
  （例如 `DELETE /api/v1/items` 之类一律不实现）。
- 命令行为：

  ```bash
  vkeyd purge --db <path>            # 默认 = dry-run：列出墓碑并给总数，不写库
  vkeyd purge --db <path> --dry-run  # 同上（显式写法）
  vkeyd purge --db <path> --yes      # 真正删除：单事务，完成后打印删除条数
  ```

  - 只影响 `items` 表中 `deleted_at IS NOT NULL AND deleted_at != 0` 的行；
    无墓碑时打印「没有已逻辑删除的条目」并以 0 退出。
  - `--dry-run` 与 `--yes` 同时给出时以 `--dry-run` 为准（更安全），并在 stderr 提示。
  - 防御断言：删除在单事务内执行，只有「实际影响行数 == 事务内统计的墓碑数」
    且「删除前后非墓碑行数完全一致」才提交，否则回滚并报错退出。
- **范围**：本策略只覆盖 `items`。`item_conflicts` / `pairs` / `audit`
  等表的清理不在本次范围内（需要时另行设计，且同样只走控制台）。

## M1 已知边界

- 仅单账号（`users` 表可容纳多行，但 CLI 与策略只操作最早创建的账号）。
- 无 TLS/ACME 内置实现（由 nginx + certbot 承担）。
- 无 APK/MSI 构建（Linux 的 `.tar.gz` 由 `linux/scripts/build-artifacts.sh` 产出）。
- 冲突副本 `item_conflicts` 只落库，暂无查询 API（运维可直接查 sqlite）。
- sqlite 单连接串行；详见 `ASYNC.md` 的边界说明。
