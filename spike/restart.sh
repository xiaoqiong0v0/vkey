#!/bin/bash
# 重启 uhid spike 守护进程（无缓冲 + 时间戳日志）
SPIKE=/home/afubek/proj/uhid-fido/spike
for p in $(pgrep -f 'uhid_fido.py'); do
  kill "$p" 2>/dev/null
done
sleep 1
cd "$SPIKE" || exit 1
nohup bash -c 'python3 -u "$0" 2>&1 | while IFS= read -r line; do printf "%s %s\n" "$(date +%H:%M:%S)" "$line"; done' \
  "$SPIKE/uhid_fido.py" > /var/tmp/uhid.log 2>&1 &
sleep 2
echo "== 进程 =="
pgrep -af uhid_fido.py
echo "== 日志 =="
tail -4 /var/tmp/uhid.log
echo "== hidraw =="
grep -il fido /sys/class/hidraw/hidraw*/device/uevent
