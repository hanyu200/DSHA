#!/system/bin/sh
# DSHA chroot 运行时 —— 阶段 0.5 真机冒烟脚本（只读探测 + 一次性最小链验证）
#
# 为什么要独立脚本：实施计划 §3 阶段 0.5 要求「先于任何 Java 改动」在主力机上把最小
# chroot 链跑通，并把结论书面记录下来。这一步的结论会直接决定：
#   ① PID ns 默认开还是关（§2.2）；② 是否需要随包静态 toybox（§2.2 工具来源）；
#   ③ setpriv 降权后 dsh 状态目录是否可写（阶段 3 才发现就要返工 rootfs 打包参数）；
#   ④ setpriv 只改 UID/GID 不改 SELinux 上下文，权限面比上游 app 域宽多少（§2.2 / §5）。
#
# 用法（在手机上以 root 身份跑；KernelSU 下 su 会弹授权）：
#     su
#     SCRIPT=/data/local/tmp/dsha-chroot-smoke.sh
#     sh "$SCRIPT" probe     # 只读探测，不改任何东西（先跑这个）
#     sh "$SCRIPT" chain     # 建 ns + 挂载 + chroot + setpriv + node
#     sh "$SCRIPT" pidns     # PID ns 孤儿/僵尸回收对比（开/关各一次）
#     sh "$SCRIPT" web       # 在 chroot 内真起一次 dsh web（可选，较重）
#     sh "$SCRIPT" cleanup   # 回收（只清自己建的东西）
#
# 怎么把脚本放到手机上（任选一种）：
#   A. MT 管理器 / 文件管理器：把 dsha-chroot-stage0-smoke.sh 拷到 /sdcard/Download/，
#      然后在 root shell 里 `cp /sdcard/Download/dsha-chroot-stage0-smoke.sh /data/local/tmp/`。
#   B. adb：`adb push dsha-chroot-stage0-smoke.sh /data/local/tmp/`
#   注意：直接从 /sdcard 执行会被 SELinux 拒绝（noexec），必须先 cp 到 /data/local/tmp。
#
#
# 报告默认写到 /data/data/com.dsh.client/files/chroot-probe/report.txt（同目录另有 report.json），
# 可用 DSHA_CHROOT_OUT=/data/local/tmp/dsha-chroot-smoke 改到别处。
#
# 安全边界（照着仓库规范写，不要改）：
#   * 不按裸 PID / 端口 / 进程名发信号；只对本次登记并核验过出生身份的 PID 发 TERM。
#   * 不碰 DSHA 正式数据：只在 /root 下建 .chroot-smoke* 临时文件，报告里逐个列出并删除。
#   * 不修改 rootfs 内任何文件（可写性探测只做 touch+rm 自己的临时文件）。
#   * 不 unmount 任何不是本脚本自己挂上的挂载点。

set -u

CHROOT_DIR="${DSHA_CHROOT_DIR:-/data/data/com.dsh.client/files/linux/ubuntu}"
APP_PKG="${DSHA_CHROOT_PKG:-com.dsh.client}"
# 报告默认写到应用私有目录：root 与 app UID 都能读写，设置页「运行环境探测」直接读这份。
# /data/local/tmp 在部分机型上 app 域读不到（SELinux），要手工 cp 出来才看得到。
OUT_DIR="${DSHA_CHROOT_OUT:-/data/data/${DSHA_CHROOT_PKG:-com.dsh.client}/files/chroot-probe}"
REPORT="$OUT_DIR/report.txt"
JSON="$OUT_DIR/report.json"
STATE="$OUT_DIR/state"
PID_NS="${DSHA_CHROOT_PIDNS:-0}"

R="$CHROOT_DIR"
NS_PID=""
MOUNTS_MADE=""

# ---------------------------------------------------------------- 记录工具

log() {
  printf '%s\n' "$*" >>"$REPORT"
  printf '%s\n' "$*"
}

section() {
  log ""
  log "==================== $* ===================="
}

# run <标签> <命令...>：记录退出码与实际输出（截断到 40 行），不做任何判断。
run() {
  label="$1"
  shift
  out="$("$@" 2>&1)"
  code=$?
  log "--- $label"
  log "\$ $*"
  printf '%s\n' "$out" | head -40 | sed 's/^/    /' >>"$REPORT"
  printf '%s\n' "$out" | head -40 | sed 's/^/    /'
  log "    [exit=$code]"
  return $code
}

# jrec <键> <值>：往 JSON 里追加一条字符串记录（不做转义，值里不要带引号）。
jrec() {
  printf '  "%s": "%s",\n' "$1" "$(printf '%s' "$2" | tr -d '"\\' | tr '\n' ' ')" >>"$JSON.tmp"
}

# kv <键> <值>：写机器可读的一行（App 侧 ChrootProbe.parse 直接读 report.txt，不引 JSON 解析器）。
#   check.<名>=yes|no   —— 硬判据：root / unshare / chroot / setpriv
#   fact.<名>=<值>      —— 只记录不拦截的项
#   exit.<名>=<退出码>  —— 原始证据
kv() {
  printf '%s=%s\n' "$1" "$2" >>"$REPORT"
}

json_start() {
  : >"$JSON.tmp"
  printf '{\n' >>"$JSON.tmp"
  jrec "device" "$(getprop ro.product.model 2>/dev/null)"
  jrec "android" "$(getprop ro.build.version.release 2>/dev/null)"
  jrec "sdk" "$(getprop ro.build.version.sdk 2>/dev/null)"
  jrec "kernel" "$(uname -r 2>/dev/null)"
  jrec "pagesize" "$(getconf PAGESIZE 2>/dev/null)"
  jrec "rootfs" "$R"
  jrec "pidNamespace" "$PID_NS"
}

json_end() {
  printf '  "_": ""\n}\n' >>"$JSON.tmp"
  mv "$JSON.tmp" "$JSON"
}

# ---------------------------------------------------------------- 前置

preflight() {
  mkdir -p "$OUT_DIR" 2>/dev/null
  : >"$REPORT"
  json_start

  section "0. 身份与 SELinux 上下文"
  run "whoami 身份" id
  run "SELinux 当前上下文 attr/current" cat /proc/self/attr/current
  run "SELinux 当前上下文 id -Z" id -Z
  run "SELinux 强制模式" getenforce
  run "su 是否真的给到 uid 0" sh -c 'test "$(id -u)" = 0 && echo ROOT_OK || echo ROOT_NO'
  jrec "selinuxBefore" "$(cat /proc/self/attr/current 2>/dev/null)"
  kv "fact.selinux_before" "$(cat /proc/self/attr/current 2>/dev/null)"

  section "1. rootfs 身份"
  if [ -d "$R" ]; then
    log "rootfs 存在：$R"
    run "rootfs 属主" stat -c '%u:%g %a %n' "$R"
    run "rootfs 顶层" ls -la "$R"
    run "/bin/bash 是否就位" ls -l "$R/bin/bash"
    run "bash ELF" sh -c "head -c 4 '$R/bin/bash' | od -An -tx1"
    run "loader 路径" sh -c "ls -l '$R/lib/ld-linux-aarch64.so.1' 2>&1 || ls -l '$R/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'"
    jrec "rootfsPresent" "yes"
  else
    log "!! rootfs 不存在：$R"
    log "   请确认 DSHA 已装好环境（设置 → 安装与修复 → 完整安装），或用 DSHA_CHROOT_DIR 指到别的 rootfs"
    jrec "rootfsPresent" "no"
    json_end
    exit 2
  fi

  APP_UID="$(stat -c '%u' /data/data/$APP_PKG 2>/dev/null)"
  APP_GID="$(stat -c '%g' /data/data/$APP_PKG 2>/dev/null)"
  [ -n "$APP_UID" ] || APP_UID="$(stat -c '%u' "$(dirname "$(dirname "$R")")" 2>/dev/null)"
  [ -n "$APP_GID" ] || APP_GID="$APP_UID"
  log "应用 UID:GID = ${APP_UID:-?}:${APP_GID:-?}"
  jrec "appUid" "${APP_UID:-?}"
  kv "fact.app_uid" "${APP_UID:-?}"
  printf '%s\n' "${APP_UID:-}" >"$STATE.uid"
  printf '%s\n' "${APP_GID:-}" >"$STATE.gid"
}

# ---------------------------------------------------------------- 能力探测

# emit_checks：把硬判据写成 check.<名>=yes|no。
# 每一项都要求「工具真的存在」且「核心命令真的能跑」—— 只看 command -v 会把
# 「装着个跑不动的玩具」当成通过，那正是 fail-closed 最怕的假阳性。
emit_checks() {
  # (a) root：su 是否真的给到 uid 0
  if [ "$(id -u 2>/dev/null)" = "0" ]; then kv "check.root" "yes"; else kv "check.root" "no"; fi
  kv "exit.root" "$(id -u 2>/dev/null || echo -1)"

  # (b) mount namespace
  if command -v unshare >/dev/null 2>&1; then
    unshare -m true >/dev/null 2>&1
    if [ $? -eq 0 ]; then kv "check.unshare" "yes"; else kv "check.unshare" "no"; fi
  else
    kv "check.unshare" "no"
  fi

  # (c) chroot 本体：工具在 + rootfs 在 + bash 在 + 真的 chroot 进去能跑
  chroot_ok=no
  if [ -d "$R" ] && [ -f "$R/bin/bash" ] && command -v chroot >/dev/null 2>&1; then
    chroot "$R" /bin/sh -c 'exit 0' >/dev/null 2>&1
    [ $? -eq 0 ] && chroot_ok=yes
  fi
  kv "check.chroot" "$chroot_ok"

  # (d) setpriv：没有它就只能以 root 跑 dsh，宿主停止链路整条失效 —— 见 §2.2
  if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid="${APP_UID:-0}" --regid="${APP_GID:-0}" --clear-groups true >/dev/null 2>&1
    if [ $? -eq 0 ]; then kv "check.setpriv" "yes"; else kv "check.setpriv" "no"; fi
  else
    kv "check.setpriv" "no"
  fi
}

probe_tools() {
  section "2. 宿主工具可用性（决定是否要随包静态 toybox）"
  for t in su unshare nsenter mount umount chroot setpriv toybox busybox id stat getconf node; do
    p="$(command -v "$t" 2>/dev/null)"
    if [ -n "$p" ]; then
      log "  OK   $t -> $p"
    else
      log "  MISS $t"
    fi
  done
  # setpriv 是关键：没有它就只能 chroot 后仍是 root，停止链路（app UID 发信号）会失效。
  if command -v setpriv >/dev/null 2>&1; then
    jrec "setpriv" "yes"
    run "setpriv 版本" setpriv --version
    run "setpriv 支持的选项" sh -c 'setpriv --help 2>&1 | head -20'
  else
    jrec "setpriv" "no"
    log "!! 缺 setpriv —— 见 §2.2：必须降回应用 UID，否则 Web 进程是 root，宿主停止链路打不到它"
  fi
  run "toybox 提供的关键子命令" sh -c 'toybox 2>/dev/null | tr " " "\n" | grep -E "^(mount|umount|chroot|unshare|nsenter|setsid|setpriv)$" | tr "\n" " "'
}

probe_unshare() {
  section "3. mount / PID namespace 可建性"
  unshare -m true >/dev/null 2>&1
  code=$?
  log "unshare -m true -> exit=$code"
  jrec "unshareMount" "$code"
  kv "exit.unshare" "$code"

  unshare -m sh -c 'mount -t tmpfs tmpfs /mnt 2>&1 && echo TMPFS_OUTSIDE_OK && umount /mnt' >/dev/null 2>&1
  tmpfs_code=$?
  log "ns 内挂 tmpfs 到 /mnt -> exit=$tmpfs_code"
  jrec "tmpfsOutsideRoot" "$tmpfs_code"
  kv "exit.tmpfs" "$tmpfs_code"

  if unshare -mpf true >/dev/null 2>&1; then
    log "unshare -mpf true -> OK（PID ns 可建）"
    jrec "pidNamespaceBuildable" "yes"
    kv "fact.pid_ns" "yes"
  else
    log "unshare -mpf true -> FAIL（PID ns 不可建）"
    jrec "pidNamespaceBuildable" "no"
    kv "fact.pid_ns" "no"
  fi

  # /proc/self/setgroups：userns 才需要；root 不需要 userns，记录以备诊断。
  if [ -e /proc/self/setgroups ]; then
    run "/proc/self/setgroups" cat /proc/self/setgroups
  fi
}

# ---------------------------------------------------------------- rootfs 可写性

probe_writability() {
  section "4. 降权后可写性（阶段 3 才发现就要返工 rootfs 打包参数）"
  uid="$APP_UID"
  gid="$APP_GID"
  tmp="$R/root/.chroot-smoke-write.$$"
  if command -v setpriv >/dev/null 2>&1 && [ -n "$uid" ]; then
    out="$(setpriv --reuid="$uid" --regid="$gid" --clear-groups sh -c "
      for d in /root /root/.dsh /usr/local/lib/node_modules /tmp; do
        if [ -d \"\$d\" ]; then
          if touch \"\$d/.chroot-smoke.$$\" 2>/dev/null; then
            echo \"  WRITABLE \$d\"; rm -f \"\$d/.chroot-smoke.$$\"
          else
            echo \"  DENIED   \$d\"
          fi
        else
          echo \"  MISSING  \$d\"
        fi
      done
      echo \"  uid=\$(id -u) euid=\$(id -u) selinux=\$(cat /proc/self/attr/current 2>/dev/null)\"
    " 2>&1)"
    log "以 ${uid}:${gid} 身份（未 chroot，路径按宿主解析）的写入探测："
    printf '%s\n' "$out" | sed 's/^/    /' >>"$REPORT"
    printf '%s\n' "$out" | sed 's/^/    /'
  else
    log "跳过：缺 setpriv 或 UID 未知"
  fi
  if [ -d "$R/root/.dsh" ]; then
    run "rootfs 内 /root/.dsh 属主" stat -c '%u:%g %a %n' "$R/root/.dsh"
    log "注意：宿主视角的属主 == 应用 UID 才说明 ①宿主可以直接读写、②chroot 内降权后也能写"
  else
    log "/root/.dsh 不存在（尚未首次运行 dsh，属正常）"
  fi
  [ -e "$tmp" ] && rm -f "$tmp"
}

# ---------------------------------------------------------------- 最小链

chain_build() {
  section "5. 最小 chroot 链（unshare/mount/chroot/setpriv/node）"
  if ! command -v unshare >/dev/null 2>&1; then
    log "!! 没有 unshare，链路无法继续"
    return 1
  fi

  # 一个自包含的引导脚本：整条链在一个 mount ns 里跑完。用 sh -c 传递，
  # 避免在 /data/local/tmp 落第二个文件（SELinux 下那里是 shell 域，未必能执行）。
  BOOT="$OUT_DIR/boot.sh"
  cat >"$BOOT" <<BOOTEOF
#!/system/bin/sh
set -u
R="$R"
UID_APP="$APP_UID"
GID_APP="$APP_GID"
PIDNS="$PID_NS"
fail=0

step() { printf '  [boot] %s\n' "\$*"; }
try()  { if "\$@" >/dev/null 2>&1; then return 0; else return 1; fi; }

step "mount ns 内 propagation -> private"
mount --make-rprivate / 2>/dev/null || mount --make-private / 2>/dev/null || true

step "rootfs self-bind（防挂载逃逸：chroot 前先把 rootfs 自己绑一次）"
if try mount --bind "\$R" "\$R"; then step "  self-bind OK"; else step "  self-bind FAIL"; fail=1; fi

step "挂 /proc"
if try mount -t proc proc "\$R/proc"; then step "  proc OK"; else
  if try mount --bind /proc "\$R/proc"; then step "  proc via bind OK"; else step "  proc FAIL"; fail=1; fi
fi

step "挂 /sys、/dev"
try mount --bind /sys "\$R/sys" && step "  sys OK" || { step "  sys FAIL"; fail=1; }
try mount --bind /dev "\$R/dev" && step "  dev OK" || { step "  dev FAIL"; fail=1; }

step "挂 /dev/pts（PTY 终端要用真 devpts）"
if try mount -t devpts devpts "\$R/dev/pts"; then step "  devpts OK"; echo DEVPTS=devpts; else
  if try mount --bind /dev/pts "\$R/dev/pts"; then step "  devpts via bind OK"; echo DEVPTS=bind; else step "  devpts FAIL"; echo DEVPTS=no; fi
fi

step "挂 /dev/shm"
mkdir -p "\$R/dev/shm" 2>/dev/null
if try mount -t tmpfs -o size=64m tmpfs "\$R/dev/shm"; then step "  shm OK"; else step "  shm FAIL（非致命）"; fi

step "挂 /tmp（tmpfs 限额）"
if try mount -t tmpfs -o size=256m tmpfs "\$R/tmp"; then step "  tmp tmpfs OK"; echo TMPFS=yes; else step "  tmp tmpfs FAIL（退回普通目录）"; echo TMPFS=no; fi

step "挂 /sys/fs/selinux（只读，诊断用）"
if [ -d /sys/fs/selinux ] && [ -d "\$R/sys/fs/selinux" ]; then
  try mount --bind /sys/fs/selinux "\$R/sys/fs/selinux" && step "  selinuxfs OK" || step "  selinuxfs FAIL（非致命）"
fi

step "chroot 前 SELinux 上下文: \$(cat /proc/self/attr/current 2>/dev/null)"
echo "SELINUX_BEFORE=\$(cat /proc/self/attr/current 2>/dev/null)"

step "chroot + 降权 + exec"
exec chroot "\$R" /bin/sh -c '
  echo "  [in-chroot] uid=\$(id -u) gid=\$(id -g)"
  echo "SELINUX_AFTER=\$(cat /proc/self/attr/current 2>/dev/null)"
  echo "  [in-chroot] selinux=\$(cat /proc/self/attr/current 2>/dev/null)"
  echo "  [in-chroot] pwd=\$(pwd) root=\$(ls -d / 2>/dev/null)"
' 2>&1
BOOTEOF
  chmod 0755 "$BOOT" 2>/dev/null

  log "引导脚本：$BOOT"
  log "启动：unshare -m --propagation private [+ -p -f] sh $BOOT"
  log ""

  if [ "$PID_NS" = "1" ]; then
    out="$(unshare -mpf --propagation private sh "$BOOT" 2>&1)"
  else
    out="$(unshare -m --propagation private sh "$BOOT" 2>&1)"
  fi
  code=$?
  printf '%s\n' "$out" >>"$REPORT"
  printf '%s\n' "$out"

  # 挂载结果与 SELinux 上下文转成机器可读项，供 App 侧 ChrootProbe.parse 读取。
  case "$(printf '%s\n' "$out" | sed -n 's/^DEVPTS=//p' | tail -1)" in
    devpts|bind) kv "fact.devpts" "yes" ;;
    *) kv "fact.devpts" "no" ;;
  esac
  case "$(printf '%s\n' "$out" | sed -n 's/^TMPFS=//p' | tail -1)" in
    yes) kv "fact.tmpfs" "yes" ;;
    *) kv "fact.tmpfs" "no" ;;
  esac
  kv "fact.selinux_after" "$(printf '%s\n' "$out" | sed -n 's/^SELINUX_AFTER=//p' | tail -1)"

  log "[exit=$code]"
  jrec "bootExit" "$code"
  kv "exit.boot" "$code"
  return $code
}

# ---------------------------------------------------------------- 降权 + node

node_chain() {
  section "6. 降权后跑 node（真链的关键一步）"
  if ! command -v setpriv >/dev/null 2>&1; then
    log "!! 缺 setpriv：本项无法验证。见 §2.2 —— 不降权则 Web 是 root，宿主停止链路失效"
    jrec "setprivNode" "skipped-no-setpriv"
    return 1
  fi
  BOOT2="$OUT_DIR/boot-node.sh"
  cat >"$BOOT2" <<BOOTEOF
#!/system/bin/sh
set -u
R="$R"
step() { printf '  [boot] %s\n' "\$*"; }
mount --make-rprivate / 2>/dev/null || true
mount --bind "\$R" "\$R" 2>/dev/null
mount -t proc proc "\$R/proc" 2>/dev/null || mount --bind /proc "\$R/proc" 2>/dev/null
mount --bind /sys "\$R/sys" 2>/dev/null
mount --bind /dev "\$R/dev" 2>/dev/null
mount -t devpts devpts "\$R/dev/pts" 2>/dev/null || mount --bind /dev/pts "\$R/dev/pts" 2>/dev/null
mkdir -p "\$R/dev/shm" 2>/dev/null
mount -t tmpfs -o size=64m tmpfs "\$R/dev/shm" 2>/dev/null
mount -t tmpfs -o size=256m tmpfs "\$R/tmp" 2>/dev/null
step "以 root 进 chroot，再用 setpriv 降回应用 UID 执行 node"
exec chroot "\$R" /usr/bin/env -i \\
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TMPDIR=/tmp \\
  /bin/sh -c '
    echo "  [in-chroot root] uid=\$(id -u) selinux=\$(cat /proc/self/attr/current 2>/dev/null)"
    exec setpriv --reuid=$APP_UID --regid=$APP_GID --clear-groups /bin/sh -c "
      echo \\"  [dropped] uid=\\\\\$(id -u) gid=\\\\\$(id -g)\\"
      echo \\"  [dropped] selinux=\\\\\$(cat /proc/self/attr/current 2>/dev/null)\\"
      echo \\"  [dropped] pwd=\\\\\$(pwd)\\"
      command -v node
      node --version
      node -e \"console.log(\\\\\\"NODE_EXEC_OK\\\\\\", process.version)\"
      echo \\"  [dropped] 可写性：\\"
      for d in /root /root/.dsh /tmp; do
        if [ -d \\"\\\\\$d\\" ]; then
          if touch \\"\\\\\$d/.smoke.\\\\\$\\\\$\\" 2>/dev/null; then echo \\"    WRITABLE \\\\\$d\\"; rm -f \\"\\\\\$d/.smoke.\\\\\$\\\\$\\"; else echo \\"    DENIED   \\\\\$d\\"; fi
        else echo \\"    MISSING  \\\\\$d\\"; fi
      done
      exit 0
    "
  ' 2>&1
BOOTEOF
  chmod 0755 "$BOOT2" 2>/dev/null
  out="$(unshare -m --propagation private sh "$BOOT2" 2>&1)"
  code=$?
  printf '%s\n' "$out" >>"$REPORT"
  printf '%s\n' "$out"
  log "[exit=$code]"
  jrec "nodeInChrootExit" "$code"
  return $code
}

# ---------------------------------------------------------------- PID ns 回收测试

pid_ns_recycle() {
  section "7. PID ns 孤儿/僵尸回收测试（决定 §2.2 的 PID ns 默认值）"
  log "做法：bash -c 'sleep 3 &' —— bash 立刻退出，sleep 成孤儿，3 秒后退出。"
  log "      开/关 PID ns 各跑一次，看 PID 1 是否即时回收、ps 是否堆积 <defunct>。"

  # 观察脚本放进 rootfs 自己（独立文件，不用嵌套引号），结果写 chroot 内的同一路径。
  RECYCLE_HOST="$OUT_DIR/recycle"
  RECYCLE_GUEST="$R${OUT_DIR#/}/recycle"
  mkdir -p "$OUT_DIR" 2>/dev/null
  rm -f "$RECYCLE_HOST.on" "$RECYCLE_HOST.off" 2>/dev/null
  cat >"$R/tmp/dsha-recycle.sh" <<'RECYCLEEOF'
#!/bin/bash
# PID ns 回收观察：起一个立刻退出的 bash，让 sleep 成孤儿，随后每秒钟数一次僵尸。
tag="$1"
last=0
echo "  我的 pid=$$"
/bin/bash -c 'sleep 3 &'
for i in 1 2 3 4 5 6; do
  sleep 1
  last=$(ps -eo stat 2>/dev/null | grep -c Z)
  printf '  t=%ss defunct=%s\n' "$i" "$last"
done
printf '%s\n' "$last" > "$2"
echo "  结束时的进程表："
ps -ef 2>/dev/null | head -20
RECYCLEEOF
  chmod 0755 "$R/tmp/dsha-recycle.sh" 2>/dev/null

  for mode in off on; do
    log ""
    log "-- PID ns ${mode} 的回收观察"
    if [ "$mode" = "on" ]; then
      out="$(unshare -mpf --propagation private chroot "$R" /bin/bash /tmp/dsha-recycle.sh on "$RECYCLE_GUEST.on" 2>&1)"
      code=$?
    else
      out="$(unshare -m --propagation private chroot "$R" /bin/bash /tmp/dsha-recycle.sh off "$RECYCLE_GUEST.off" 2>&1)"
      code=$?
    fi
    printf '%s\n' "$out" >>"$REPORT"
    printf '%s\n' "$out"
    log "[exit=$code]"
    jrec "pidRecycle_$mode" "$code"
    kv "exit.pid_recycle_$mode" "$code"
  done

  rm -f "$R/tmp/dsha-recycle.sh" 2>/dev/null

  # 判定：开 PID ns 跑完后僵尸数必须回到 0，否则说明 PID 1 不回收 → §2.2 保持关闭。
  final_on="$(cat "$RECYCLE_HOST.on" 2>/dev/null)"
  if [ -n "$final_on" ] && [ "$final_on" = "0" ]; then
    kv "fact.pid_ns_recycle" "yes"
    log "判定：开 PID ns 时僵尸回落到 0 → 回收正常"
  else
    kv "fact.pid_ns_recycle" "no"
    log "判定：开 PID ns 时僵尸最终为 ${final_on:-未知}（非 0 或未取到）→ 不启用 PID ns"
  fi
  log "判读：若 defunct 在 t=3s 后不回落，说明没有 subreaper 的 PID ns 会累积僵尸 → §2.2 保持 PID ns 关闭。"
}

# ---------------------------------------------------------------- 可选：真起 dsh web

web_chain() {
  section "8. 在 chroot 内真起一次 dsh web（可选，较重）"
  log "复用 DSHA 自己的哨兵与 pid 文件契约："
  log "  哨兵 $R/root/.dsha-stopped，pid 文件 $R/root/.dsha-web.pid"
  log "  本脚本只写自己的一次性探针文件 .dsha-chroot-smoke.pid，不动正式 .dsha-web.pid"
  BOOT3="$OUT_DIR/boot-web.sh"
  cat >"$BOOT3" <<BOOTEOF
#!/system/bin/sh
set -u
R="$R"
mount --make-rprivate / 2>/dev/null || true
mount --bind "\$R" "\$R" 2>/dev/null
mount -t proc proc "\$R/proc" 2>/dev/null || mount --bind /proc "\$R/proc" 2>/dev/null
mount --bind /sys "\$R/sys" 2>/dev/null
mount --bind /dev "\$R/dev" 2>/dev/null
mount -t devpts devpts "\$R/dev/pts" 2>/dev/null || mount --bind /dev/pts "\$R/dev/pts" 2>/dev/null
mkdir -p "\$R/dev/shm" 2>/dev/null
mount -t tmpfs -o size=64m tmpfs "\$R/dev/shm" 2>/dev/null
mount -t tmpfs -o size=256m tmpfs "\$R/tmp" 2>/dev/null
exec chroot "\$R" /usr/bin/env -i \\
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TMPDIR=/tmp \\
  DSH_HOME=/root/.dsh BROWSER=true DSH_CONFIRM=1 \\
  /bin/sh -c '
    echo \\"  [web] uid=\\\\\$(id -u) selinux=\\\\\$(cat /proc/self/attr/current 2>/dev/null)\\"
    cd /root || exit 1
    echo \\"\\\\\$\\\\$\\" > /root/.dsha-chroot-smoke.pid
    exec setpriv --reuid=$APP_UID --regid=$APP_GID --clear-groups /bin/bash -c \\"
      exec dsh web --no-open --host 127.0.0.1 --port 3080
    \\"
  ' 2>&1
BOOTEOF
  chmod 0755 "$BOOT3" 2>/dev/null

  # 后台起 ns，保留 pid 以便按出生身份核验后回收。
  unshare -m --propagation private sh "$BOOT3" >"$OUT_DIR/web.log" 2>&1 &
  nspid=$!
  log "ns 启动者 PID=$nspid（仅用于本次回收，脚本会先核验 cmdline 再发 TERM）"
  printf '%s\n' "$nspid" >"$STATE.nspid"

  i=0
  while [ "$i" -lt 40 ]; do
    sleep 1
    i=$((i + 1))
    if grep -q "http://127.0.0.1" "$OUT_DIR/web.log" 2>/dev/null; then
      log "第 ${i}s 抓到启动行："
      grep -o "http://127.0.0.1:[0-9]*[^ ]*" "$OUT_DIR/web.log" | head -3 | sed 's/^/    /' >>"$REPORT"
      grep -o "http://127.0.0.1:[0-9]*[^ ]*" "$OUT_DIR/web.log" | head -3
      jrec "webUrl" "found"
      break
    fi
  done
  if [ "$i" -ge 40 ]; then
    log "40s 内没抓到鉴权 URL，日志尾部："
    tail -30 "$OUT_DIR/web.log" | sed 's/^/    /' >>"$REPORT"
    tail -30 "$OUT_DIR/web.log"
    jrec "webUrl" "not-found"
  fi
  log "web.log 全文：$OUT_DIR/web.log"
  log "确认完请跑 cleanup 回收。"
}

cleanup() {
  section "9. 回收"
  nspid="$(cat "$STATE.nspid" 2>/dev/null)"
  if [ -n "${nspid:-}" ]; then
    # 出生身份核验：cmdline 必须是本脚本的引导脚本，才允许发 TERM。
    if tr '\0' ' ' <"/proc/$nspid/cmdline" 2>/dev/null | grep -q "boot-web.sh\|boot-node.sh\|dsha-chroot-smoke"; then
      log "核验通过，给 PID $nspid 发 TERM"
      kill -TERM "$nspid" 2>/dev/null
      sleep 2
      if kill -0 "$nspid" 2>/dev/null; then
        log "仍未退出，再等 3s"
        sleep 3
      fi
    else
      log "PID $nspid 的 cmdline 不是本脚本的引导脚本，拒绝发信号（保留现场）"
    fi
    rm -f "$STATE.nspid"
  else
    log "没有登记的 ns PID"
  fi

  # 只清自己建的文件。
  rm -f "$R/root/.dsha-chroot-smoke.pid" 2>/dev/null && log "已删 /root/.dsha-chroot-smoke.pid"
  rm -f "$R"/root/.chroot-smoke* "$R"/root/.smoke.* 2>/dev/null
  rm -f "$R"/tmp/.chroot-smoke.* 2>/dev/null
  log "临时文件已清理（rootfs 内未做其它改动）"
  log "报告：$REPORT / $JSON"
}

# ---------------------------------------------------------------- 主入口

case "${1:-probe}" in
  probe)
    preflight
    emit_checks
    probe_tools
    probe_unshare
    probe_writability
    section "结论速查"
    log "把本文件（$REPORT）整份回贴即可；重点看："
    log "  1) check.setpriv 是否为 yes（no → 必须随包静态 toybox，且停止链路会失效）"
    log "  2) check.root / check.unshare / check.chroot 是否为 yes"
    log "  3) fact.selinux_before / fact.selinux_after（setpriv 前后是否变化）"
    log "  4) /root/.dsh 属主是否 == 应用 UID（fact.app_uid）"
    json_end
    ;;
  chain)
    preflight
    chain_build || true
    node_chain || true
    json_end
    ;;
  pidns)
    preflight
    chain_build >/dev/null 2>&1 || true
    pid_ns_recycle || true
    json_end
    ;;
  web)
    preflight
    web_chain
    json_end
    ;;
  cleanup)
    cleanup
    ;;
  *)
    echo "用法: sh $0 {probe|chain|pidns|web|cleanup}"
    exit 1
    ;;
esac

log ""
log "完成。"
