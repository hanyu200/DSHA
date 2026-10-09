# DSHA chroot 运行时 fork —— 实现与验证报告

> 基座：`https://github.com/DSH-APP/DSHA`，`main` @ **`006254e`**
> （`fix: 同步 build170 真机确认的 ADB 冷目录与离线准备修复`，versionCode 170 /
> `0.2.21-20261009.0750-dsh0.2.0-rc.2` / 内置 dsh `0.2.0-rc.2`）
> 分支：`feat/chroot-runtime`　实施依据：《DSHA 三运行时 Fork 实施方案》v1.3
> 本报告日期：2026-10-09

## 一、目标与范围

在**保留** proot / proroot 两个现有运行时的前提下新增 **chroot** 运行时，选择顺序
`chroot（有 root 且探测通过）→ proroot → proot`，由能力探测决定；无 root 用户体验与上游
完全一致（零回归）。本轮覆盖实施方案的阶段 0 → 2（阶段 3 真机验收由用户执行）。

## 二、基座与计划的差异（实施前必须知道）

实施计划 v1.3 是照 **v0.1.7-rc2 / versionCode 147 / dsh 0.1.7-rc.2** 写的，而当前仓库
已经前进到 versionCode 170 / dsh 0.2.0-rc.2。计划里以下内容**按实况更正**：

| 计划 | 实况 |
|---|---|
| §1.3 资产 `offline-rootfs.bin` sha `b9fe8a04…`、version 10 | 当前期望 `0a680b56…`；`docs/接手指南.md` 与 `recovery-runtime/lock.json` 里记录的 `b9fe8a04…` 是历史值 |
| §1.3 `dsh-runtime.bin` 116.5MB | 当前 `3ddafc8f83fec8f13b9dfec7d51686af1d1aa82771e8dd0a65efb913d03b7bbb`（本机按仓库锁重新生成后**逐字节吻合**） |
| §4「既有 172 测试类全绿」 | `app/src/test` 实际 **283** 个 `*Test.java`（`AGENTS.md` 那句 172 自身已过期） |
| §2.5「仿 `docs/device-acceptance-*.md`」 | 该模板不存在；`docs/device-acceptance-2026-09-05.md` 等是具体记录，验收统一写 `docs/releases/` |
| §2.2「把 `ContainerRuntime.BINDS` 逐条转 `mount --bind`」 | 不能照抄：`/proc/self/fd` 是符号链接、`/dev/urandom → /dev/random` 是文件绑定、`/dev/pts` 与 `/dev` 绑定重复 |
| §1.1「两个 flavor」 | 正确（`standard` / `low`），本报告未改动 flavor |

## 三、实现清单

### 新增（纯逻辑，`util/`，全部配单测）

| 文件 | 职责 |
|---|---|
| `util/ChrootProbe.java` | 探测结论的结构化记录 + 确定性选择 + 报告解析 + 文本/JSON 导出 + 结论保鲜 |
| `util/RuntimeSelection.java` | 四选一偏好 + 探测结论 ⟹ 本次用谁 + 降级阶梯（proot 是终点） |
| `util/RuntimeFallback.java` | 失败归因：只有运行时层签名才允许降级，默认「不降级」 |

### 新增（runtime / assets）

| 文件 | 职责 |
|---|---|
| `runtime/ChrootHostScripts.java` | 引导脚本按内容摘要落到应用私有目录只读槽位；每次装配前复核字节 |
| `runtime/ChrootProbeStore.java` | 探测结论落盘与读取；路径与真机冒烟脚本一致 |
| `assets/chroot/host-launch.sh` | 启动链：`unshare -m` → 挂载 → `exec` 监护进程（降回应用 UID）→ 哨兵停止 |
| `assets/chroot/host-ctl.sh` | 诊断与兜底：`status` / `stop` / `teardown` / `mounts` / `probe`（全部按出生身份核验后才发信号） |
| `docs/chroot-stage0-smoke.sh` | 阶段 0.5 真机冒烟脚本（探测 + 最小链 + PID ns 回收对比 + 降权 node + 报告导出） |

### 修改

| 文件 | 改动 |
|---|---|
| `runtime/ContainerRuntime.java` | 新增 `envMode()` / `appendsGuestCommand()` / `bindsThroughLauncher()` / `hostShell()` 四个契约（老实现走默认值，行为不变）+ `Chroot` 实现 |
| `runtime/RuntimeLauncher.java` | 改为向运行时要 `hostShell`；`HOST_SCRIPT` 模式下把命令与 bind 清单经环境变量交给脚本 |
| `runtime/RuntimeExecution.java` | `runtime()` 成为唯一决策点（探测 + 偏好 + 资产可用性 → 运行时） |
| `runtime/RuntimeHostPorts.java` | `Settings` 增加 `runtimeChoice`（老 4 参数构造保留） |
| `core/ConfigStore.java` | `runtimeMode()` / `setRuntimeMode()`；`runtimeSettingsFrom` 带出档位；`preferFastColdModeFrom` 语义随档位扩展调整 |
| `util/WebProcSel.java` | 认得出 chroot 引导链，且明确不当信号目标（守住既有不变式） |
| `ui/ConfigFragment.java` | 运行方式四选一；选择写回并通过历史布尔开关保持冷安装核验可用 |
| `app/build.gradle` | fork 递增版本码 171 / `0.2.22-20261009.1200-dsh0.2.0-rc.2` |
| `CHANGELOG.md` | 本轮条目（含语义变化与已知差异） |

### 不变式（计划要求守住）

`ShellQuote`（chroot 的 argv 不再依赖引号拼接）、`Query`、`BackupScope`、
`DeviceShellPolicy`（**未**通过设备命令通道执行 su/mount —— 那里 `mount` 属显式拒绝）、
`WebProcSel`（已扩测）。`ColdRuntimeSelection` 未改（`KEY_CONTAINER_RUNTIME` 仍是同一键）。

## 四、本机验证结果

```bash
# 纯逻辑单测（javac + JUnitCore，绕开 aapt2/AGP）
ChrootProbeTest RuntimeSelectionTest RuntimeFallbackTest
WebProcSelTest WebProcSelChrootTest ConfigStoreRuntimeSettingsTest ColdRuntimeSelectionTest
→ OK (71 tests)
```

- 改动过的 runtime/util/core 类含**完整依赖闭包** javac 编译通过（326 个 class）。
- 冷启动路径校验：`tools/prepare-backup-assets.py --write` 用本机生成的 `dsh-runtime.bin`
  跑完 588 条受管包证明，产物与仓库已提交版本**逐字节一致** —— 说明本机生成的 dsh 覆盖层
  与受管资产合同吻合。
- `assets/chroot/*.sh` 过 `bash -n`。
- `ConfigFragment.java` UI 改动做 `javac -proc:only` 解析检查（clean）；**未做完整编译**
  （见下）。

### 本机未能验证的部分（如实声明，不得当作通过）

| 项 | 原因 |
|---|---|
| Gradle 全量单测 / Release Lint / APK 打包 | 缺 `offline-rootfs.bin`（Ubuntu arm64 userland 只能在 Linux 上 debootstrap）；本机亦无 NDK 26.3.11579264 |
| `runtime-descriptor.json` 重新生成 | 同一原因：生成器要求 `asset_paths()` 包含 `offline-rootfs.bin`。**因此 `verifyRuntimeDescriptorInputs` 当前为红**（`DESCRIPTOR_LAUNCHER_MEMBER_SET`），因为 `launcherSources` 里的 `util/WebProcSel.java` 与 `core/ConfigStore.java` 摘要已变。发布前必须在有 Linux 环境的机器上跑 `tools/prepare-runtime-descriptor.py --write` 并提交该产物，否则门禁失败 |
| `ubuntu-tools.bin` | 锁文件里 28 个 deb 有 **13 个**已被 Ubuntu 从 `ports.ubuntu.com` 撤下（`curl` / `openssl` / `perl` 等被更新版本取代），固定版本不再可下载。需要重跑 `tools/prepare-ubuntu-tools.py` 的取锁流程，或改用 snapshot 镜像 —— 属上游维护问题，非本 fork 引入 |
| 真机链路（阶段 0.5 / 阶段 3） | 由用户在设备上按 `docs/chroot-stage0-smoke.sh` + 验收清单执行 |

## 五、设计上的两处刻意选择

1. **PID ns 在 v1 内不实现**。监护进程不能是另一个 PID namespace 的 PID 1（内核特殊对待，
   且它退出会连带杀掉整个 ns），而把 guest 单独放进 ns 又会让 pid 文件同时存在「宿主可见 pid」
   与「ns 内 pid」两个语义。计划 §2.2 要求的「先有经测试的 subreaper 方案再开」就是这个意思。
   `host-launch.sh` 收到 `DSHA_CHROOT_PIDNS=1` 时会明确说明并降级为关闭，`ChrootProbe`
   也只在**可建且回收实测通过**时才建议开启。
2. **监护进程先降回应用 UID 再写 pid 文件**。这是让「停止」不需要 `su -c kill` 的关键：
   降权后宿主与它同 UID，`WebProcessManager` 那套「pid 文件 + `/proc/<pid>/stat` 出生身份
   核验」原样可用；留在 root 则既杀不动、pid 文件也读不了。

## 六、未决问题

1. `runtime-descriptor.json` 需在有 Linux 环境的机器上重新生成后提交（见上表）。
2. `ubuntu-tools.bin` 的 13 个固定版本 deb 已被上游撤下，需要重新取锁或改镜像。
3. 阶段 0.5 结论（`setpriv` 是否存在 / PID ns 回收 / 降权后可写性 / su 的 SELinux 域）
   决定：是否需要随包静态 toybox、是否评估降域、rootfs 属主是否需要调整。
4. SELinux 域差异（应用 UID + su 域）需在阶段 2/3 评估降域可行性，受机型 sepolicy 限制；
   默认保持并已在 CHANGELOG 与本报告中如实记录。
5. `RuntimeTrial` / 冷安装仍走 proot（与计划 §2.3 一致）；chroot 目前只服务日常启动链，
   受管更新路径的 chroot 化留给阶段 4。
