#!/usr/bin/env bash
# 把 vkeyd 交叉编译并部署到 ECS（仅手动执行；CI 与本仓库都不会自动运行）。
#
# 用法：
#   ./server/deploy/deploy.sh           # dry-run（默认）：只打印计划，不做任何改动
#   ./server/deploy/deploy.sh --apply   # 真执行
#
# 脚本做的六步（与 ECS 实际部署一致）：
#   1. 编译 server/cmd/vkeyd -> .tmp/scratch/vkeyd-linux-<ARCH>
#   2. 上传二进制到 <REMOTE_DIR>/bin/vkeyd.new，并上传 unit / nginx 配置到远端 /tmp
#   3. 安装 nginx vhost（sites-available + sites-enabled 软链）并 `nginx -t`；
#      失败则立即用备份回滚并退出（不会 reload，也不会重启服务）
#   4. 安装 systemd unit（User=ecs-user，ReadWritePaths 只放开数据目录）
#   5. 备份旧二进制为 vkeyd.prev，替换并 `systemctl restart vkeyd`
#   6. `systemctl reload nginx` 后做健康检查
#
# 环境变量（均有与实际部署一致的默认值）：
#   REMOTE      目标主机        默认 ecs-user@47.97.78.223
#   REMOTE_DIR  远端根目录（须绝对路径）  默认 /home/ecs-user/work/vkey
#   DOMAIN      域名            默认 vkey.xiaoqiong0v0.cn
#   ARCH        目标架构        默认 amd64
#   SERVICE     systemd 单元名  默认 vkeyd
#   SITE        nginx 站点文件名 默认 <DOMAIN>.conf
#   WEBROOT     ACME webroot    默认 /var/www/html
#
# 首次部署（尚无证书）请先按 server/README.md 的「两阶段上线」走一遍：
# 脚本在证书缺失时会跳过 nginx 配置安装，只更新二进制与 unit。

set -euo pipefail

REMOTE="${REMOTE:-ecs-user@47.97.78.223}"
REMOTE_DIR="${REMOTE_DIR:-/home/ecs-user/work/vkey}"
DOMAIN="${DOMAIN:-vkey.xiaoqiong0v0.cn}"
ARCH="${ARCH:-amd64}"
SERVICE="${SERVICE:-vkeyd}"
SITE="${SITE:-${DOMAIN}.conf}"
WEBROOT="${WEBROOT:-/var/www/html}"

BIN="${REMOTE_DIR}/bin/vkeyd"
DB="${REMOTE_DIR}/data/vkeyd.db"
SITE_PATH="/etc/nginx/sites-available/${SITE}"
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT="${REPO_ROOT}/.tmp/scratch/vkeyd-linux-${ARCH}"
TS="$(date +%Y%m%d-%H%M%S)"
BK="/etc/nginx/backup-${TS}"

usage() {
  # 打印文件头部的注释块（到 set -euo pipefail 为止），不依赖固定行号。
  awk '/^set -euo pipefail/{exit} NR>1 && /^#/{sub(/^# ?/,""); print}' "$0"
}

APPLY=0
for arg in "$@"; do
  case "${arg}" in
    --apply) APPLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：${arg}（见 --help）" >&2; exit 2 ;;
  esac
done

if [ "${APPLY}" -ne 1 ]; then
  cat <<EOF
将执行以下操作（dry-run，未做任何改动）：
  1. 编译 server/cmd/vkeyd -> ${OUT}（CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH}）
  2. scp 二进制 -> ${REMOTE}:${BIN}.new
     scp nginx 配置 -> ${REMOTE}:/tmp/vkey-nginx.conf
     scp systemd unit -> ${REMOTE}:/tmp/vkeyd.service
  3. 备份现有 nginx 配置到 ${BK}/，安装 ${SITE_PATH}（+ sites-enabled 软链）
     然后 sudo nginx -t；失败则回滚到备份并退出
  4. 备份并安装 /etc/systemd/system/${SERVICE}.service，daemon-reload
  5. 旧二进制备份为 vkeyd.prev，替换后 sudo systemctl restart ${SERVICE}
  6. sudo systemctl reload nginx，健康检查 https://${DOMAIN}/api/v1/health

真执行请加开关：./server/deploy/deploy.sh --apply
EOF
  exit 1
fi

echo "==> [1/6] 编译（linux/${ARCH}）"
mkdir -p "$(dirname "${OUT}")"
(
  cd "${REPO_ROOT}/server"
  CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
    go build -trimpath -ldflags="-s -w" -o "${OUT}" ./cmd/vkeyd
)
echo "    产物: ${OUT} ($(wc -c < "${OUT}") 字节)"

echo "==> [2/6] 上传二进制与配置"
ssh "${REMOTE}" "mkdir -p '${REMOTE_DIR}/bin' '${REMOTE_DIR}/data'"
scp -q "${OUT}" "${REMOTE}:${BIN}.new"
scp -q "${HERE}/nginx-vkey.conf" "${REMOTE}:/tmp/vkey-nginx.conf"
scp -q "${HERE}/vkeyd.service" "${REMOTE}:/tmp/vkeyd.service"

echo "==> [3/6] 安装 nginx 配置并校验"
NGINX_RESULT="$(
  ssh "${REMOTE}" "TS='${TS}' SITE='${SITE}' SITE_PATH='${SITE_PATH}' BK='${BK}' \
    CERT='${CERT}' WEBROOT='${WEBROOT}' DOMAIN='${DOMAIN}' bash -s" <<'REMOTE_EOF'
set -eu
if [ ! -f "${CERT}" ]; then
  echo "skip:missing-cert"
  exit 0
fi
sudo -n mkdir -p "${BK}"
sudo -n cp -a "${SITE_PATH}" "${BK}/" 2>/dev/null || true
sudo -n install -m 0644 /tmp/vkey-nginx.conf "${SITE_PATH}"
sudo -n ln -sfn "${SITE_PATH}" "/etc/nginx/sites-enabled/${SITE}"
if sudo -n nginx -t >/tmp/vkey-nginx-t.log 2>&1; then
  echo "ok"
  exit 0
fi
echo "fail"
cat /tmp/vkey-nginx-t.log >&2
if sudo -n ls "${BK}/$(basename "${SITE_PATH}")" >/dev/null 2>&1; then
  sudo -n cp -a "${BK}/$(basename "${SITE_PATH}")" "${SITE_PATH}"
  echo "已回滚 nginx 配置（备份：${BK}/）" >&2
else
  sudo -n rm -f "${SITE_PATH}" "/etc/nginx/sites-enabled/${SITE}"
  echo "原本无此 vhost，已移除新装配置" >&2
fi
sudo -n nginx -t >/dev/null 2>&1 || echo "警告：回滚后 nginx -t 仍失败，请人工检查" >&2
exit 1
REMOTE_EOF
)" || { echo "!! nginx 配置安装失败，已回滚，未重启服务" >&2; exit 1; }

case "${NGINX_RESULT}" in
  skip:missing-cert)
    echo "    证书缺失（${CERT}），跳过 nginx 配置安装"
    echo "    两阶段上线：先只启用 80 块，再执行"
    echo "      sudo certbot certonly --webroot -w ${WEBROOT} -d ${DOMAIN}"
    ;;
  *) echo "    nginx -t 通过，配置已安装（备份目录 ${BK}/）" ;;
esac

echo "==> [4/6] 安装 systemd unit"
ssh "${REMOTE}" "TS='${TS}' SERVICE='${SERVICE}' bash -s" <<'REMOTE_EOF'
set -eu
sudo -n cp -a "/etc/systemd/system/${SERVICE}.service" \
  "/etc/systemd/system/${SERVICE}.service.bak-${TS}" 2>/dev/null || true
sudo -n install -m 0644 /tmp/vkeyd.service "/etc/systemd/system/${SERVICE}.service"
sudo -n systemctl daemon-reload
REMOTE_EOF

echo "==> [5/6] 替换二进制并重启 ${SERVICE}"
ssh "${REMOTE}" "BIN='${BIN}' SERVICE='${SERVICE}' bash -s" <<'REMOTE_EOF'
set -eu
cd "$(dirname "${BIN}")"
if [ -f vkeyd ]; then cp -a vkeyd vkeyd.prev; fi
mv -f vkeyd.new vkeyd
chmod 755 vkeyd
sudo -n systemctl restart "${SERVICE}"
systemctl --no-pager --lines=12 status "${SERVICE}" || true
REMOTE_EOF

echo "==> [6/6] reload nginx 并健康检查"
ssh "${REMOTE}" "sudo -n systemctl reload nginx"

ok=0
for _ in 1 2 3 4 5; do
  if curl -fsS "https://${DOMAIN}/api/v1/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [ "${ok}" -ne 1 ]; then
  echo "!! 健康检查失败。回滚二进制：" >&2
  echo "   ssh ${REMOTE} 'cd $(dirname "${BIN}") && cp -a vkeyd.prev vkeyd && sudo systemctl restart ${SERVICE}'" >&2
  exit 1
fi
echo "    健康检查通过"

cat <<EOF

==> 完成。后续：
  - 健康检查：curl -fsS https://${DOMAIN}/api/v1/health
  - 日志：    ssh ${REMOTE} 'journalctl -u ${SERVICE} -n 50 --no-pager'
  - 证书：    sudo certbot renew --dry-run   # webroot ${WEBROOT}，续期后 reload nginx
  - 回滚：    二进制 ${BIN}.prev；unit 备份 /etc/systemd/system/${SERVICE}.service.bak-${TS}；
              nginx 配置备份 ${BK}/
EOF
