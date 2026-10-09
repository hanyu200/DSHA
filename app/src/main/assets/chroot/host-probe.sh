#!/system/bin/sh
# DSHA chroot 运行时 —— 设置页「运行环境探测」用的只读探测脚本
#
# 与 docs/chroot-stage0-smoke.sh probe 是同一套判据（同一个 check./fact. 键），区别只在：
#   * 这份由 App 经 su 调起，报告直接输出到 stdout（App 落盘成 report.txt），
#     因此不写 /data/local/tmp、不建临时文件、不需要 DSHA_CHROOT_OUT；
#   * 只做探测，**不**建命名空间、**不**挂载、**不**起容器 —— 可以随时反复跑。
#
# 输出格式（ChrootProbe.parse 直接读，一行一条）：
#   check.root=yes|no        su 是否真的给到 uid 0
#   check.unshare=yes|no     mount namespace 可建
#   check.chroot=yes|no      工具在 + rootfs 在 + 真的 chroot 进去能跑
#   check.setpriv=yes|no      能降回应用 UID（缺它则宿主停止链路失效，见方案 §2.2）
#   fact.*=…                 只记录不拦截的项
#
# 环境变量（由 App 提供）：
#   DSHA_CHROOT_PKG   应用包名（默认 com.dsh.client）
#   DSHA_CHROOT_DIR   rootfs 路径（默认 /data/data/<pkg>/files/linux/ubuntu）

set -u

PKG="${DSHA_CHROOT_PKG:-com.dsh.client}"
R="${DSHA_CHROOT_DIR:-/data/data/$PKG/files/linux/ubuntu}"

kv() { printf '%s=%s\n' "$1" "$2"; }

# ---------------------------------------------------------------- 硬判据

# (a) root：su 是否真的给到 uid 0
if [ "$(id -u 2>/dev/null)" = "0" ]; then kv check.root yes; else kv check.root no; fi
kv exit.root "$(id -u 2>/dev/null || echo -1)"

# 应用 UID/GID：降权目标与可写性判据都要用
APP_UID="$(stat -c '%u' "/data/data/$PKG" 2>/dev/null)"
[ -n "$APP_UID" ] || APP_UID="$(stat -c '%u' "$(dirname "$(dirname "$R")")" 2>/dev/null)"
case "$APP_UID" in ''|*[!0-9]*) APP_UID="" ;; esac
kv fact.app_uid "${APP_UID:-unknown}"

# (b) mount namespace
if command -v unshare >/dev/null 2>&1; then
  if unshare -m true >/dev/null 2>&1; then kv check.unshare yes; else kv check.unshare no; fi
else
  kv check.unshare no
fi

# (c) chroot 本体：工具 + rootfs + /bin/bash + 真的进得去
chroot_ok=no
if [ -d "$R" ] && [ -f "$R/bin/bash" ] && command -v chroot >/dev/null 2>&1; then
  if chroot "$R" /bin/sh -c 'exit 0' >/dev/null 2>&1; then chroot_ok=yes; fi
fi
kv check.chroot "$chroot_ok"
kv fact.rootfs_present "$([ -d "$R" ] && echo yes || echo no)"
kv fact.rootfs_bash "$([ -f "$R/bin/bash" ] && echo yes || echo no)"
if [ -d "$R" ]; then
  kv fact.rootfs_owner "$(stat -c '%u:%g' "$R" 2>/dev/null)"
fi

# (d) setpriv：缺它就只能以 root 跑 dsh，宿主（app UID）打不到信号
setpriv_ok=no
if command -v setpriv >/dev/null 2>&1; then
  target="${APP_UID:-0}"
  if setpriv --reuid="$target" --regid="$target" --clear-groups true >/dev/null 2>&1; then
    setpriv_ok=yes
  fi
fi
kv check.setpriv "$setpriv_ok"

# ---------------------------------------------------------------- 记录项

# PID ns 可建性（默认可建≠该开：还要看孤儿回收，那要跑进程，本探测不做）
if unshare -mpf true >/dev/null 2>&1; then kv fact.pid_ns yes; else kv fact.pid_ns no; fi

# tmpfs 可挂（只读探测：在自建的 ns 里试一次，退出即消失）
if unshare -m sh -c 'mount -t tmpfs tmpfs /mnt >/dev/null 2>&1 && umount /mnt >/dev/null 2>&1' >/dev/null 2>&1; then
  kv fact.tmpfs yes
else
  kv fact.tmpfs no
fi

# devpts 可挂（PTY 终端要用）
if unshare -m sh -c 'mount -t devpts devpts /dev/pts >/dev/null 2>&1' >/dev/null 2>&1; then
  kv fact.devpts yes
else
  kv fact.devpts no
fi

# SELinux 上下文：setpriv 只改 UID/GID、不改域，这里记录 su 域供文档比对
kv fact.selinux_before "$(cat /proc/self/attr/current 2>/dev/null | tr -d '\n')"

# 页大小：16K 页设备的标记
kv fact.pagesize "$(getconf PAGESIZE 2>/dev/null || echo unknown)"

# 宿主工具可用性：缺哪个决定是否需要随包静态 toybox
for tool in unshare chroot setpriv mount umount nsenter; do
  if command -v "$tool" >/dev/null 2>&1; then kv "fact.tool_$tool" yes; else kv "fact.tool_$tool" no; fi
done

# 降权后可写性（只 touch + rm 自己的临时文件，不改 rootfs 其它内容）
if [ "$setpriv_ok" = "yes" ] && [ -n "$APP_UID" ]; then
  write_report="$(
    setpriv --reuid="$APP_UID" --regid="$APP_UID" --clear-groups sh -c "
      for d in /root /root/.dsh; do
        if [ -d \"\$d\" ]; then
          if touch \"\$d/.probe.$$\" 2>/dev/null; then echo \"\$d=yes\"; rm -f \"\$d/.probe.$$\"; else echo \"\$d=no\"; fi
        fi
      done
    " 2>/dev/null
  )"
  for line in $write_report; do kv "fact.writable_$(printf '%s' "${line%%=*}" | tr -c 'a-zA-Z0-9' '_')" "${line##*=}"; done
fi

# 版本标记：报告里带上，便于判断结论是哪一版脚本产出的
kv fact.probe_version 1

exit 0
