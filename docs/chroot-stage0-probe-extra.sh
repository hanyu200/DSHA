#!/system/bin/sh
# 阶段 0.5 补充取证：跨域信号权限、残留目录来源、UID 映射。
OUT=/data/local/tmp/probe-extra.txt
exec >"$OUT" 2>&1

echo "=== 1. SELinux 里 untrusted_app 能不能给 ksu 域发信号 ==="
POL=/sys/fs/selinux/policy
echo "policy: $(ls -l $POL 2>&1)"
if command -v sesearch >/dev/null 2>&1; then
  echo "--- sesearch allow untrusted_app ksu process ---"
  sesearch -A -s untrusted_app -t ksu -c process 2>&1 | head -20
  echo "--- sesearch allow untrusted_app ksu file ---"
  sesearch -A -s untrusted_app -t ksu -c file 2>&1 | head -10
else
  echo "sesearch 不存在，改用原始策略 grep"
  for dom in untrusted_app untrusted_app_25 untrusted_app_27 untrusted_app_29 untrusted_app_30 untrusted_app_31 untrusted_app_32 untrusted_app_33 untrusted_app_34; do
    hit=$(grep -a -o "$dom *ksu *process *{[^}]*}" "$POL" 2>/dev/null | head -1)
    [ -n "$hit" ] && echo "  $hit"
  done
  echo "--- 含 ksu 的 allow 行（最多 15 条）---"
  grep -a -o 'allow [a-z_]* ksu:[a-z]* {[^}]*}' "$POL" 2>/dev/null | sort -u | head -15
  echo "--- untrusted_app 对 ksu 的任何规则 ---"
  grep -a -o 'allow untrusted_app[a-z_0-9]* ksu:[a-z]* {[^}]*}' "$POL" 2>/dev/null | sort -u | head -15
  echo "--- ksu 域类型是否存在 ---"
  grep -a -c 'ksu' "$POL" 2>/dev/null
fi

echo
echo "=== 2. 残留目录 /data/data/com.dsh.client 是什么 ==="
D=/data/data/com.dsh.client
echo "--- stat ---"
stat "$D" 2>&1
echo "--- 内容 ---"
ls -la "$D" 2>&1 | head -20
echo "--- 大小 ---"
du -sh "$D" 2>&1
echo "--- 是不是符号链接 / 指向哪 ---"
readlink -f "$D" 2>&1
echo "--- 包管理器里有没有 ---"
pm list packages -u 2>/dev/null | grep -i 'com.dsh.client' || echo "  (packages -u 里也没有)"
pm path com.dsh.client 2>&1

echo
echo "=== 3. UID 映射 ==="
echo "--- shell 用户 ---"
id 2>&1
echo "--- 已安装应用 UID 样本（前 15 个）---"
for p in $(pm list packages 2>/dev/null | head -15 | sed 's/package://'); do
  u=$(stat -c %u "/data/data/$p" 2>/dev/null)
  echo "  $u  $p"
done

echo
echo "=== 4. /data/user 与 /data/data 的关系 ==="
ls -ld /data/data /data/user /data/user/0 2>&1
echo "--- 同一个包在两个路径下的 inode 是否一致 ---"
stat -c '%i %n' /data/data/com.dsh.client 2>&1
stat -c '%i %n' /data/user/0/com.dsh.client 2>&1

echo
echo "=== 5. 当前设备上 chroot 相关工具的全貌 ==="
for t in chroot unshare nsenter mount su runcon setenforce toybox; do
  printf '  %-10s %s\n' "$t" "$(command -v $t 2>/dev/null || echo MISS)"
done
echo "  busybox     $(command -v busybox 2>/dev/null || echo MISS)"
echo "--- busybox 带哪些降权/域相关 applet ---"
busybox --list 2>/dev/null | tr ' ' '\n' | grep -x -E 'setuidgid|chpst|setpriv|runcon|runuser|su|nsenter|chroot|unshare' | tr '\n' ' '
echo
echo "--- toybox 是否有 runcon ---"
toybox 2>/dev/null | tr ' ' '\n' | grep -x -E 'runcon|setenforce|chcon' | tr '\n' ' '
echo

echo
echo "=== 完成 ==="
