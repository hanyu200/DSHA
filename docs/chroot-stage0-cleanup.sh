#!/system/bin/sh
# 精确清理阶段 0.5 测试留下的东西。只碰列出的路径，不做任何递归进 /proc 的动作。
exec 2>&1

echo "=== 1. 卸载指向测试目录的挂载（从深到浅）==="
# 从 /proc/self/mountinfo 取挂载点，过滤出测试目录，按路径深度倒序卸载。
for base in /data/local/tmp/miniroot /data/local/tmp/miniroot2 /data/local/tmp/miniroot3 \
            /data/local/tmp/miniroot4 /data/local/tmp/mr5 /data/local/tmp/mr6; do
  # 该 base 下的挂载点，深的先来
  points=$(grep -F " $base" /proc/self/mountinfo 2>/dev/null | awk '{print $5}' | sort -r)
  for p in $points; do
    [ -n "$p" ] || continue
    if umount "$p" 2>/dev/null; then
      echo "  umount $p"
    elif umount -l "$p" 2>/dev/null; then
      echo "  umount -l $p"
    else
      echo "  卸载失败（非致命）$p"
    fi
  done
done

echo
echo "=== 2. 删目录（此时应无挂载）==="
for d in /data/local/tmp/miniroot /data/local/tmp/miniroot2 /data/local/tmp/miniroot3 \
         /data/local/tmp/miniroot4 /data/local/tmp/mr5; do
  if [ -e "$d" ]; then
    rm -rf "$d" && echo "  删除 $d" || echo "  删除失败 $d"
  fi
done

echo
echo "=== 3. 删文件 ==="
for f in /data/local/tmp/mr6-result.txt /data/local/tmp/probe-extra.txt /data/local/tmp/t3.pid \
         /data/local/tmp/probe-drop.sh /data/local/tmp/probe-extra.sh; do
  rm -f "$f" && echo "  删除 $f"
done

echo
echo "=== 4. 残留检查 ==="
echo "--- 仍指向测试目录的挂载 ---"
grep -E 'miniroot|mr5|mr6' /proc/self/mountinfo 2>/dev/null | awk '{print "  " $5}' || true
echo "--- /data/local/tmp 内容 ---"
ls /data/local/tmp/
echo "--- 空壳包目录 ---"
if [ -d /data/data/com.dsh.client ]; then
  echo "  仍存在，删除"
  rm -rf /data/data/com.dsh.client && echo "  已删除" || echo "  删除失败"
else
  echo "  已不存在"
fi
echo
echo "=== 完成 ==="
