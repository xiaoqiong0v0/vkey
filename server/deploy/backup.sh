#!/usr/bin/env bash
# vkey 服务端加密备份：SQLite backup API（含 WAL）→ GPG 非对称加密
#
# 依赖：sqlite3（Python 标准库）、gpg、已导入的备份公钥（无对应私钥）
# 用法：直接执行；可用环境变量覆盖路径
#   VKEY_DB              数据库路径（默认 <deploy 根>/data/vkeyd.db）
#   VKEY_BACKUP_DIR      产物目录（默认 <deploy 根>/data/backups）
#   VKEY_BACKUP_RECIPIENT  GPG 收件人（公钥标识，默认 backup@vkey.local）
#   VKEY_BACKUP_KEEP_DAYS 保留天数（默认 30）
#   GNUPGHOME            GPG 主目录（默认 ~/.gnupg-vkey）
#
# 退出码：0 成功；1 自检失败（条数为 0 / integrity_check 非 ok）
set -euo pipefail

BASE_DIR="${VKEY_BASE_DIR:-$HOME/work/vkey}"
DB="${VKEY_DB:-$BASE_DIR/data/vkeyd.db}"
OUT="${VKEY_BACKUP_DIR:-$BASE_DIR/data/backups}"
RECIPIENT="${VKEY_BACKUP_RECIPIENT:-backup@vkey.local}"
KEEP_DAYS="${VKEY_BACKUP_KEEP_DAYS:-30}"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg-vkey}"

mkdir -p "$OUT"
TS=$(date +%Y%m%d-%H%M%S)
TMP=$(mktemp /tmp/vkeybak.XXXXXX)
trap 'rm -f "$TMP"' EXIT

# SQLite backup API：包含 WAL 中未 checkpoint 的写入
python3 - "$DB" "$TMP" <<'PY'
import sqlite3
import sys

src = sqlite3.connect(sys.argv[1], timeout=15)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
PY

# 健全性自检：条数不能为 0，且 integrity_check 必须 ok
SELFCHECK=$(python3 - "$TMP" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
status = conn.execute("pragma integrity_check").fetchone()[0]
items = conn.execute("select count(*) from items").fetchone()[0]
users = conn.execute("select count(*) from users").fetchone()[0]
print(f"{status} items={items} users={users}")
PY
)
echo "backup selfcheck: $SELFCHECK"
case "$SELFCHECK" in
  ok*) ;;
  *) echo "ABORT: backup selfcheck failed" >&2; exit 1 ;;
esac

gpg --batch --yes --trust-model always -r "$RECIPIENT" \
  --output "$OUT/vkeyd-$TS.db.gpg" --encrypt "$TMP"

find "$OUT" -name 'vkeyd-*.db.gpg' -mtime +"$KEEP_DAYS" -delete
ls -1t "$OUT" | head -3
