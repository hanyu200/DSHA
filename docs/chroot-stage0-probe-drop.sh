#!/system/bin/sh
# 阶段 0.5 降权链验证：chroot + setuidgid 能不能真正把 UID 降下来。
# 判据：AFTER uid 必须是非 0，且 pid 与 before 相同（exec 原地降权，不 fork）。

BB=/data/adb/ksu/bin/busybox
ROOT=/data/local/tmp/mr6
U=2000
OUT=/data/local/tmp/mr6-result.txt

exec >"$OUT" 2>&1
echo "=== 环境 ==="
echo "shell id: $(id -u)"
echo "busybox: $BB ($(test -x "$BB" && echo executable || echo NOT-executable))"

cleanup() {
  umount "$ROOT/tmp" 2>/dev/null
  umount "$ROOT/dev" 2>/dev/null
  umount "$ROOT/proc" 2>/dev/null
  umount "$ROOT" 2>/dev/null
}
cleanup
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/tmp"
cp "$BB" "$ROOT/bin/busybox"
chmod 755 "$ROOT/bin/busybox"
for a in sh id cat ls sleep setuidgid; do ln -sf busybox "$ROOT/bin/$a"; done
echo hello-from-miniroot >"$ROOT/probe.txt"

cat >"$ROOT/inner.sh" <<'EOS'
export PATH=/bin
echo "  before uid=$(id -u) gid=$(id -g) pid=$$"
exec /bin/setuidgid 2000 /bin/sh /after.sh
EOS

cat >"$ROOT/after.sh" <<'EOS'
export PATH=/bin
echo "  AFTER  uid=$(id -u) gid=$(id -g) pid=$$"
echo "  AFTER  ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "  AFTER  read=$(cat /probe.txt 2>&1)"
EOS

echo
echo "=== 跑主链 ==="
unshare -m "$BB" sh -c "
  R='$ROOT'
  mount --make-rprivate / 2>/dev/null
  mount --bind \"\$R\" \"\$R\" || { echo 'self-bind FAIL'; exit 1; }
  mount -t proc proc \"\$R/proc\" 2>/dev/null || mount --bind /proc \"\$R/proc\" 2>/dev/null
  mount --bind /dev \"\$R/dev\" 2>/dev/null
  echo '  mounts done'
  exec $BB chroot \"\$R\" /bin/sh /inner.sh
"
echo "  unshare exit=$?"

echo
echo "=== 收集现场 ==="
echo "--- 挂载残留（应只剩 rootfs 自己那条，或者为空）---"
grep -F "$ROOT" /proc/self/mountinfo 2>/dev/null | awk '{print "    " $5}' || echo "    （无）"

echo "--- 清理 ---"
cleanup
echo "    完成"

echo
echo "=== 结论 ==="
if grep -q 'AFTER  uid=2000' "$OUT"; then
  echo "PASS: setuidgid 降权成功"
elif grep -q 'AFTER  uid=0' "$OUT"; then
  echo "FAIL: setuidgid 是空操作（uid 仍为 0）"
elif grep -q 'AFTER' "$OUT"; then
  echo "PARTIAL: 看到 AFTER 行但不是 2000 —— 见上文"
else
  echo "FAIL: 没走到降权步骤"
fi
