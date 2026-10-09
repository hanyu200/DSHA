#!/system/bin/sh
# DSHA chroot 运行时 —— 宿主侧启动脚本（以 root 经 su 执行）
#
# 职责边界（照着仓库规范划的，不要在这里扩）：
#   * 本脚本只做「建命名空间 → 挂载 → 起 guest → 监护 → 拆挂载」；
#   * 命令文本、环境变量、PID 文件与哨兵路径全部来自调用方（Java 侧），脚本自己不做判断，
#     也不认识 dsh —— 换 dsh 版本、换 profile、换端口都不需要改这里；
#   * 自己写 pid 文件（出生身份由 Java 侧从 /proc/<pid>/stat 读取后另行登记）。
#
# 为什么监护进程要降回应用 UID 再 exec（计划 §2.2 只说了「降权跑 dsh」，这里多说一句）：
#   mount namespace 的生命周期 = 里面最后一个进程。如果监护进程留在 root，
#   宿主（app UID）既杀不动它，也没法用现有「pid 文件 + 出生身份」链路停它 ——
#   于是「停止」会退化成 `su -c kill`，那正是仓库明令禁止的「按裸 PID 发信号」。
#   降回应用 UID 后：停止链路原样可用、SIGTERM 能直达 guest、namespace 随进程退出自动消亡。
#
# 调用契约（Java 侧 ChrootRuntime 负责装配，全部经环境变量传入，不进 argv）：
#   DSHA_CHROOT_ROOTFS     rootfs 宿主绝对路径（必填）
#   DSHA_CHROOT_APP_UID    降权目标 uid（必填）
#   DSHA_CHROOT_APP_GID    降权目标 gid（必填）
#   DSHA_CHROOT_COMMAND    guest 内要执行的 shell 命令（必填；已由 ShellQuote 处理）
#   DSHA_CHROOT_PIDFILE    宿主侧 pid 文件绝对路径（必填）
#   DSHA_CHROOT_SENTINEL   宿主侧哨兵绝对路径（必填；存在即请求停止）
#   DSHA_CHROOT_LOGFILE    guest 输出追加重定向目标（可空）
#   DSHA_CHROOT_BINDS      额外 bind 清单，每行一条 host:guest（可空）
#   DSHA_CHROOT_PIDNS      1 = 开 PID namespace（默认 0，见计划 §2.2）
#   DSHA_CHROOT_ENVFILE    guest 环境变量文件（每行一条 NAME=VALUE；可空）
#   DSHA_CHROOT_READYFILE  就绪标记路径（挂载完成后 touch 它；可空）
#
# 安全边界：
#   * 不 unmount 任何不是本脚本自己挂上的挂载点（清单就写在下面，一一对应）；
#   * 不按裸 PID 发信号 —— 停止走哨兵，脚本只对本次 fork 出来的 $GUEST_PID 发信号；
#   * 挂载全部发生在 unshare 出来的 namespace 内，进程全退即自动清空（另保留显式 teardown）。
#
# PID ns 为什么不在这里开（计划 §2.2「默认值由阶段 0.5 冒烟结论决定」）：
#   ns 里的 PID 1 由内核特殊对待 —— 只有它能收到的信号才有默认动作，而它退出会连带杀掉
#   整个 ns。本设计里「监护进程必须能被宿主按 pid 文件核验后停掉」，所以监护进程不能是
#   另一个 ns 的 PID 1；而把 guest 单独放进 ns，又会把 pid 文件的语义拆成「宿主可见 pid」
#   与「ns 内 pid」两个数。在没有经测试的孤儿回收方案（subreaper 包装）之前，
#   这里保持关闭，并要求 §2.2 的开关结论先到位。

set -u

say() { printf '[chroot-boot] %s\n' "$*"; }
fail() { printf '[chroot-boot] ERROR: %s\n' "$*" >&2; exit 1; }

R="${DSHA_CHROOT_ROOTFS:-}"
APP_UID="${DSHA_CHROOT_APP_UID:-}"
APP_GID="${DSHA_CHROOT_APP_GID:-}"
COMMAND="${DSHA_CHROOT_COMMAND:-}"
PIDFILE="${DSHA_CHROOT_PIDFILE:-}"
SENTINEL="${DSHA_CHROOT_SENTINEL:-}"
LOGFILE="${DSHA_CHROOT_LOGFILE:-}"
BINDS="${DSHA_CHROOT_BINDS:-}"
PIDNS="${DSHA_CHROOT_PIDNS:-0}"
ENVFILE="${DSHA_CHROOT_ENVFILE:-}"
READYFILE="${DSHA_CHROOT_READYFILE:-}"

# 本脚本的绝对路径。降权后重入（setpriv sh "$SELF" __supervise-app）与进 namespace 后重入
# 都要用它 —— 那时 $0 已经不可靠，所以从一开始就固定下来。
if [ -n "${DSHA_CHROOT_SCRIPT:-}" ]; then
  SELF="$DSHA_CHROOT_SCRIPT"
else
  SELF="$0"
  case "$SELF" in
    /*) ;;
    *) SELF="$(cd "$(dirname "$SELF")" 2>/dev/null && pwd)/$(basename "$SELF")" ;;
  esac
fi

[ -n "$R" ] || fail "DSHA_CHROOT_ROOTFS 未设置"
[ -n "$COMMAND" ] || fail "DSHA_CHROOT_COMMAND 未设置"
[ -n "$PIDFILE" ] || fail "DSHA_CHROOT_PIDFILE 未设置"
[ -n "$SENTINEL" ] || fail "DSHA_CHROOT_SENTINEL 未设置"
[ -d "$R" ] || fail "rootfs 不存在：$R"
[ -x "$R/bin/bash" ] || [ -f "$R/bin/bash" ] || fail "rootfs 里没有 /bin/bash：$R"
[ "$(id -u 2>/dev/null)" = "0" ] || fail "需要 root（su 未授权？）"
case "$APP_UID" in ''|*[!0-9]*) fail "DSHA_CHROOT_APP_UID 不是数字：$APP_UID" ;; esac
case "$APP_GID" in ''|*[!0-9]*) fail "DSHA_CHROOT_APP_GID 不是数字：$APP_GID" ;; esac

for tool in unshare mount chroot setpriv; do
  command -v "$tool" >/dev/null 2>&1 || fail "缺工具：$tool（需要随包静态 toybox）"
done

# ---------------------------------------------------------------- 挂载清单

MANIFEST=""   # 反向卸载用；只登记本脚本真的挂上的点
record() { MANIFEST="$1
$MANIFEST"; }

mount_one() {
  # mount_one <类型> <目标> [额外 mount 参数…]：类型为 bind 时用 --bind，否则 -t <类型>。
  kind="$1"; target="$2"; shift 2
  if [ ! -d "$target" ]; then
    mkdir -p "$target" 2>/dev/null || { say "跳过（目录建不出来）：$target"; return 1; }
  fi
  if [ "$kind" = "bind" ]; then
    mount --bind "$1" "$target" 2>/dev/null || { say "bind 失败：$1 -> $target"; return 1; }
  else
    mount -t "$kind" "$@" "$target" 2>/dev/null || { say "挂载失败：$kind -> $target"; return 1; }
  fi
  record "$target"
  return 0
}

setup_mounts() {
  # propagation private 必须在任何挂载之前：否则挂载会往上传播到全局命名空间，
  # 卸载不干净、还会污染系统（计划 §2.2 第 1 条）。
  mount --make-rprivate / 2>/dev/null || mount --make-private / 2>/dev/null || say "警告：propagation private 未生效"

  # rootfs self-bind：chroot 前的防逃逸动作，也让 / 成为一个独立挂载点。
  mount_one bind "$R" "$R" || fail "rootfs self-bind 失败，拒绝继续"

  # /proc 用新挂载（能看到 ns 内真实进程表），失败退回 bind。
  mount_one proc "$R/proc" proc || mount_one bind "$R/proc" /proc

  mount_one bind "$R/sys" /sys
  mount_one bind "$R/dev" /dev

  # devpts 优先真挂载（PTY 终端需要），失败退回 bind。
  mount_one devpts "$R/dev/pts" devpts || mount_one bind "$R/dev/pts" /dev/pts

  mkdir -p "$R/dev/shm" 2>/dev/null
  mount_one tmpfs "$R/dev/shm" -o size=64m tmpfs

  # 限额 tmpfs：容器里的临时文件不该把应用数据分区写满。
  mount_one tmpfs "$R/tmp" -o size=256m tmpfs

  if [ -d /sys/fs/selinux ] && [ -d "$R/sys/fs/selinux" ]; then
    mount_one bind "$R/sys/fs/selinux" /sys/fs/selinux
  fi

  # 调用方补的 bind（工作区、用户选的目录等），逐条核验存在性。
  if [ -n "$BINDS" ]; then
    printf '%s\n' "$BINDS" | while IFS= read -r line; do
      [ -n "$line" ] || continue
      host="${line%%:*}"
      guest="${line#*:}"
      if [ -z "$host" ] || [ -z "$guest" ]; then say "跳过格式不对的 bind：$line"; continue; fi
      if [ ! -e "$host" ]; then say "跳过不存在的 bind 源：$host"; continue; fi
      target="$R$guest"
      if [ ! -d "$target" ]; then mkdir -p "$target" 2>/dev/null || { say "跳过（目录建不出来）：$target"; continue; }; fi
      if mount --bind "$host" "$target" 2>/dev/null; then
        say "bind $host -> $guest"
      else
        say "bind 失败：$host -> $guest"
      fi
    done
  fi
}

teardown_mounts() {
  # 反向卸载，只碰 MANIFEST 里登记过的点。
  printf '%s\n' "$MANIFEST" | while IFS= read -r point; do
    [ -n "$point" ] || continue
    umount "$point" 2>/dev/null || umount -l "$point" 2>/dev/null || true
  done
}

# ---------------------------------------------------------------- guest 环境

# 环境变量走文件而不是 argv：ps 里看不到内容（凭据护栏），也绕开了各层引号。
guest_env_prelude() {
  if [ -n "$ENVFILE" ] && [ -f "$ENVFILE" ]; then
    printf 'set -a; . %s; set +a; ' "$ENVFILE"
  fi
}

# ---------------------------------------------------------------- 监护循环

start_supervisor() {
  # PID ns 在 v1 里没有实现，且这里刻意不「顺手加上」：见文件头「PID ns 为什么不在这里开」。
  if [ "$PIDNS" = "1" ]; then
    say "PID ns 暂不支持（需要经测试的孤儿回收方案），本次按关闭处理"
  fi
  # 到这里已经在自己的 mount namespace 里、rootfs 已挂好、仍是 root：
  # 唯一要做的是把监护进程降回应用 UID，然后进入降权后的主循环。
  # 顺序不能反 —— 详见文件头「为什么监护进程要降回应用 UID 再 exec」。
  exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups \
    DSHA_CHROOT_SCRIPT="$SELF" sh "$SELF" __supervise-app
}

# 已降权：从这里开始的每一行都以应用 UID 运行。
supervise_app() {
  if [ -n "$READYFILE" ]; then : >"$READYFILE" 2>/dev/null; fi

  prelude="$(guest_env_prelude)"
  [ -n "$LOGFILE" ] && exec >>"$LOGFILE" 2>&1

  chroot "$R" /bin/bash -c "$prelude$COMMAND" &
  GUEST_PID=$!

  # pid 文件写的是 guest 的 pid（exec 之后它就是真正跑 dsh 的那个进程）。
  echo "$GUEST_PID" >"$PIDFILE" 2>/dev/null || say "警告：pid 文件写不进去：$PIDFILE"

  forwarding=0
  on_signal() {
    [ "$forwarding" = "1" ] && return 0
    forwarding=1
    kill -TERM "$GUEST_PID" 2>/dev/null
  }
  trap on_signal TERM INT HUP

  waited=0
  while kill -0 "$GUEST_PID" 2>/dev/null; do
    if [ "$forwarding" = "1" ]; then
      # 已经请求停止：给 TERM 一点时间；超时就 KILL（计划 §5「PID1 信号语义」同一条）。
      sleep 1
      waited=$((waited + 1))
      if [ "$waited" -ge 10 ]; then
        kill -KILL "$GUEST_PID" 2>/dev/null
        waited=0
      fi
      continue
    fi
    # 哨兵：仓库既有的「用户已停止」语义，拉起者每轮自己检查，看见就退出。
    if [ -e "$SENTINEL" ]; then
      kill -TERM "$GUEST_PID" 2>/dev/null
      forwarding=1
    fi
    sleep 1
  done
  wait "$GUEST_PID" 2>/dev/null
  status=$?

  # 不在这里再 su 一次去显式拆挂载。理由：挂载全在本进程所属的 mount namespace 里，
  # 「namespace 内最后一个进程退出」就是最可靠的清理点 —— 内核连挂载带 ns 一起收走。
  # 反过来，从已降权的监护进程里再 su 起一个 root 收尾进程，会引入两个新风险：
  # ① su 失败/被 SELinux 拒时留下一个半死进程占着 namespace；② 多出来一个自己的僵尸。
  # 显式 teardown 留给 host-ctl.sh（人工/诊断用），不放在自动路径上。
  say "guest 已退出（status=$status）；namespace 将随本进程退出自动清空挂载"
  exit "$status"
}

# root 域收尾：按清单反向卸载。清单靠环境传不进来（跨 su），所以这里重算一次
# 固定挂载点；额外 bind 由 namespace 消亡自动清空，不需要（也不应该）在这里猜。
teardown() {
  for point in \
    "$R/dev/shm" "$R/tmp" "$R/sys/fs/selinux" "$R/dev/pts" "$R/dev" "$R/sys" "$R/proc" "$R"; do
    [ -n "$point" ] || continue
    umount "$point" 2>/dev/null || umount -l "$point" 2>/dev/null || true
  done
  say "挂载已清理，namespace 即将消亡"
}

# ---------------------------------------------------------------- 主入口
#
# 三段式：Java 侧 su 调起本脚本 → 本脚本进 mount ns 并挂载 → exec 成监护进程。
# 用「子命令 + exec」而不是嵌套 sh -c 拼字符串：既保住 pid 不变，也免掉一层引号。

case "${1:-boot}" in
  __supervise-app)
    supervise_app
    ;;
  __teardown)
    teardown
    ;;
  boot)
    if [ "${DSHA_CHROOT_IN_NS:-0}" = "1" ]; then
      # 已经在自己的 mount namespace 里（由下面那层 unshare 起的）。
      setup_mounts
      start_supervisor
    fi
    # 用 unshare 起一个只属于自己的 mount namespace，之后的挂载都只影响它。
    # exec 保住 pid：Java 侧看到的仍是同一个进程，停止链路不需要额外映射。
    DSHA_CHROOT_IN_NS=1 exec unshare -m --propagation private sh "$0" boot
    ;;
  *)
    fail "未知子命令：$1（Java 侧只应调用 boot）"
    ;;
esac

fail "启动链没有走到监护阶段（见上面的输出）"
