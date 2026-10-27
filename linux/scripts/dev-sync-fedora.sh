#!/usr/bin/env bash
# 把 linux/ 与 shared/ 同步到 Fedora 测试机并跑 cargo test。
#
# 用法：
#   chmod +x linux/scripts/dev-sync-fedora.sh
#   VKEY_FEDORA_HOST=afubek@192.168.1.108 \
#   VKEY_FEDORA_DIR=~/proj/vkey \
#   linux/scripts/dev-sync-fedora.sh
#
# 注意：测试机当前可能不可达；脚本不会做任何 ECS / RustDesk 操作。
set -euo pipefail

HOST="${VKEY_FEDORA_HOST:-afubek@192.168.1.108}"
DEST="${VKEY_FEDORA_DIR:-~/proj/vkey}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==> 同步 linux/ 与 shared/ 到 ${HOST}:${DEST}"
# --delete 只作用于远端 linux/，避免旧文件残留；target/ 不传。
rsync -az --delete --exclude target/ "${ROOT}/linux/" "${HOST}:${DEST}/linux/"
rsync -az "${ROOT}/shared/" "${HOST}:${DEST}/shared/"

echo "==> 远端 cargo test --release"
# shellcheck disable=SC2029
ssh "${HOST}" "cd '${DEST}/linux' && cargo test --release"

echo "==> 完成"
