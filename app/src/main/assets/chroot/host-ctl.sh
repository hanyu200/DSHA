#!/system/bin/sh
# DSHA chroot 运行时 —— 宿主侧生命周期脚本（以 root 经 su 执行）
#
# 职责：status / stop / teardown / mounts / probe。
#
# 为什么停止要单独一个脚本而不是让 Java 直接 kill：
#   chroot 的启动链里有一段是 root 域的（unshare/mount）。宿主（app UID）打不到 root 进程，
#   所以「拆挂载」这类收尾必须在 root 域做。但**发信号这件事本身**遵守仓库规范：
#   只对「pid 文件里的 pid + 出生身份核验通过」的进程发 TERM，绝不按端口、进程名或裸 pid 杀。
#
# 与 WebProcessManager 的关系：正常停止路径仍然是 Java 侧写哨兵 → host-launch.sh 的监护
# 进程自己收尾（那条路径不需要特权）。本脚本是**诊断与兜底**入口：
#   诊断时用 status 看现场；监护进程意外残留时用 stop；挂载确认残留时用 teardown。
#
# 安全边界：
#   * 出生身份判据 = pid 文件里的 pid + /proc/<pid>/stat 的 starttime 与登记值一致
#     （登记文件由 ChrootLifecycle 写，格式 "<pid> <starttime>"，与 .dsha-web.identity 同构）；
#   * 身份对不上就拒绝发信号并保留现场，不做「猜一个杀掉」；
#   * teardown 只卸载清单内的点，且只在目标确实是自己人的 mount namespace 里操作。

set -u

say() { printf '[chroot-ctl] %s\n' "$*"; }
bad() { printf '[chroot-ctl] %s\n' "$*" >&2; exit 1; }

R="${DSHA_CHROOT_ROOTFS:-}"
PIDFILE="${DSHA_CHROOT_PIDFILE:-}"
IDENTITY="${DSHA_CHROOT_IDENTITY:-}"
SENTINEL="${DSHA_CHROOT_SENTINEL:-}"

usage() {
  echo "用法: sh host-ctl.sh {status|stop|teardown|mounts|probe}"
  echo "  全部参数经环境变量传入：DSHA_CHROOT_ROOTFS / DSHA_CHROOT_PIDFILE /"
  echo "  DSHA_CHROOT_IDENTITY / DSHA_CHROOT_SENTINEL"
  exit 1
}

require_root() {
  [ "$(id -u 2>/dev/null)" = "0" ] || bad "需要 root（su 未授权？）"
}

# ---------------------------------------------------------------- 出生身份

# 读 /proc/<pid>/stat 的第 22 个字段（starttime）。字段 2 是 comm，可能含空格与括号，
# 所以从最后一个 ')' 之后开始切 —— 这是内核文档给出的唯一稳妥读法。
starttime_of() {
  pid="$1"
  [ -r "/proc/$pid/stat" ] || return 1
  # shellcheck disable=SC2002
  line="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  rest="${line##*)}"
  # rest 以空格开头；第 1 个字段是 state(3)，starttime 是第 20 个。
  printf '%s\n' "$rest" | awk '{print $20}'
}

cmdline_of() {
  tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null
}

# 登记身份格式："<pid> <starttime>"，与 .dsha-web.identity 同构。
registered_identity() {
  if [ -n "$IDENTITY" ] && [ -f "$IDENTITY" ]; then
    head -c 128 "$IDENTITY" 2>/dev/null | tr -d '\n'
    return 0
  fi
  return 1
}

recorded_pid() {
  if [ -n "$PIDFILE" ] && [ -f "$PIDFILE" ]; then
    head -c 32 "$PIDFILE" 2>/dev/null | tr -d ' \n'
    return 0
  fi
  return 1
}

# 返回 0 表示「这个 pid 就是登记过的那个进程」。
identity_matches() {
  pid="$1"
  registered="$(registered_identity)" || return 1
  case "$registered" in
    "$pid "*) expected="${registered#"$pid "}" ;;
    *) return 1 ;;
  esac
  actual="$(starttime_of "$pid")" || return 1
  [ -n "$actual" ] && [ "$actual" = "$expected" ]
}

# ---------------------------------------------------------------- 子命令

do_status() {
  say "rootfs：${R:-（未设置）}"
  pid="$(recorded_pid)" || { say "无 pid 文件（${PIDFILE:-未设置}）→ 未在运行"; return 0; }
  say "pid 文件：$pid"
  if [ ! -d "/proc/$pid" ]; then
    say "结论：进程已不存在（过期记录）"
    return 0
  fi
  say "cmdline：$(cmdline_of "$pid")"
  say "starttime：$(starttime_of "$pid")"
  say "uid：$(stat -c '%u' "/proc/$pid" 2>/dev/null)"
  if identity_matches "$pid"; then
    say "出生身份：核验通过"
  else
    say "出生身份：核验不通过（登记=$(registered_identity 2>/dev/null || echo 无)）→ 拒绝把它当成我们的进程"
  fi
  if [ -n "$SENTINEL" ]; then
    if [ -e "$SENTINEL" ]; then say "哨兵：存在（已请求停止）"; else say "哨兵：不存在"; fi
  fi
}

do_stop() {
  require_root
  pid="$(recorded_pid)" || bad "没有 pid 文件，拒绝猜测目标"
  case "$pid" in ''|*[!0-9]*) bad "pid 文件内容不是单个正整数：$pid" ;; esac
  if [ ! -d "/proc/$pid" ]; then
    say "进程 $pid 已不存在"
    return 0
  fi
  identity_matches "$pid" || bad "pid $pid 出生身份与登记不符，拒绝发信号（保留现场）"

  say "核验通过，给 pid $pid 发 TERM"
  kill -TERM "$pid" 2>/dev/null || say "TERM 失败（可能已退出）"

  waited=0
  while [ -d "/proc/$pid" ] && [ "$waited" -lt 15 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if [ -d "/proc/$pid" ]; then
    say "15s 未退出，改发 KILL"
    kill -KILL "$pid" 2>/dev/null
    sleep 1
  fi
  if [ -d "/proc/$pid" ]; then
    say "结论：仍未确认退出"
    return 1
  fi
  say "结论：已停止"
}

do_mounts() {
  [ -n "$R" ] || bad "DSHA_CHROOT_ROOTFS 未设置"
  say "rootfs 下自本次链路的挂载点（读 /proc/self/mountinfo 里指向 rootfs 的项）："
  # 只看与 rootfs 前缀相关的挂载，避免把系统挂载刷屏。
  grep -F " $R" /proc/self/mountinfo 2>/dev/null | awk '{print "  " $5 "  (" $9 ")"}' || say "  （无）"
  say "提示：这些是**本脚本所在命名空间**里能看到的项。启动链的挂载在自己的 mount ns 里，"
  say "      正常情况下这里看不到；能看到残留说明有进程把那个 ns 撑住了。"
}

do_teardown() {
  require_root
  [ -n "$R" ] || bad "DSHA_CHROOT_ROOTFS 未设置"
  say "按清单反向卸载（只碰下面的点）"
  for point in \
    "$R/dev/shm" "$R/tmp" "$R/sys/fs/selinux" "$R/dev/pts" "$R/dev" "$R/sys" "$R/proc" "$R"; do
    [ -n "$point" ] || continue
    if grep -qF " $point " /proc/self/mountinfo 2>/dev/null; then
      if umount "$point" 2>/dev/null || umount -l "$point" 2>/dev/null; then
        say "已卸载 $point"
      else
        say "卸载失败 $point（可能仍被占用）"
      fi
    fi
  done
  say "完成。"
}

do_probe() {
  say "宿主能力探测（只读，不改任何东西）"
  for tool in su unshare nsenter mount umount chroot setpriv toybox busybox; do
    path="$(command -v "$tool" 2>/dev/null)"
    if [ -n "$path" ]; then say "  OK   $tool -> $path"; else say "  MISS $tool"; fi
  done
  if command -v unshare >/dev/null 2>&1; then
    unshare -m true >/dev/null 2>&1 && say "  unshare -m：OK" || say "  unshare -m：FAIL"
  fi
  if [ -n "$R" ] && [ -f "$R/bin/bash" ]; then
    if command -v chroot >/dev/null 2>&1 && chroot "$R" /bin/sh -c 'exit 0' >/dev/null 2>&1; then
      say "  chroot 进 rootfs：OK"
    else
      say "  chroot 进 rootfs：FAIL"
    fi
  else
    say "  chroot 进 rootfs：跳过（rootfs 或 /bin/bash 缺失）"
  fi
  say "  当前 SELinux 上下文：$(cat /proc/self/attr/current 2>/dev/null)"
}

case "${1:-}" in
  status)   do_status ;;
  stop)     do_stop ;;
  teardown) do_teardown ;;
  mounts)   do_mounts ;;
  probe)    do_probe ;;
  *)        usage ;;
esac
