package com.deepseekharness.app.util;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * chroot 启动链的判据断言。
 *
 * <p>这一组测试防的是两个方向相反的错：
 * <ul>
 *   <li><b>误杀</b>：把启动链认成 Web 进程 → 停止时先把它杀掉，等于把整个环境一起带走；</li>
 *   <li><b>误放</b>：认不出它 → 它带着 pids/命令文本去挡住全局停止屏障，用户点了停止却一直
 *       「未确认」。</li>
 * </ul>
 * 所以「认得出」和「能杀」必须分开断言 —— 认出来了也<b>不许</b>对它发信号（它跑在 root 域，
 * 宿主本来也打不到）。
 */
public final class WebProcSelChrootTest {

  private static final String LAUNCH =
      "/data/user/0/com.dsh.client/files/chroot/host-launch.sh";
  private static final String CTL = "/data/user/0/com.dsh.client/files/chroot/host-ctl.sh";
  private static final String ENTER = "/data/user/0/com.dsh.client/files/chroot/host-ns-enter.sh";

  /** 启动链 argv 里一定带着整条待执行命令 —— 这正是文本匹配会误命中的地方。 */
  private static final String PAYLOAD =
      "export DSH_HOME=/root/.dsh && export DSHA_STARTUP_PROFILE='web' && "
          + "export DSHA_WEB_GENERATION=7 && echo $$ > /root/.dsha-web.pid 2>/dev/null; "
          + "[ ! -e /root/.dsha-stopped ] || exit 0; "
          + "exec dsh web --no-open --host 127.0.0.1 --port 3080";

  // ---------------------------------------------------------------- 认得出

  @Test
  public void recognizesChrootLaunchChain() {
    assertTrue(WebProcSel.isChrootStarter("sh " + LAUNCH + " boot"));
    assertTrue(WebProcSel.isChrootStarter("/system/bin/sh " + LAUNCH + " boot"));
    assertTrue(
        WebProcSel.isChrootStarter(
            "unshare -m --propagation private sh " + LAUNCH + " boot"));
    assertTrue(WebProcSel.isChrootStarter(LAUNCH + " boot"));
    assertTrue(WebProcSel.isChrootStarter("sh " + LAUNCH + " boot --pidns 1"));
    assertTrue(WebProcSel.isChrootStarter(new StringBuilder().append("sh\0").append(LAUNCH)
        .append("\0boot\0").toString()));
    assertTrue(WebProcSel.isChrootStarter("sh " + CTL + " status"));
    // 子命令 + 选项：PID 这类参数一律走 --flag，形状才可判定。
    assertTrue(WebProcSel.isChrootStarter("sh " + CTL + " stop --pid 1234"));
    assertTrue(WebProcSel.isChrootStarter("sh " + ENTER + " teardown --pid 1234"));
    // 裸参数（非 -- 开头）不算启动器形状 —— 见 unknownSubcommandIsNotAStarter。
    assertFalse(WebProcSel.isChrootStarter("sh " + ENTER + " enter 1234"));
  }

  @Test
  public void recognizedChainIsNeverAWebTarget() {
    // 启动链的 argv 里明明白白写着 dsh web / bin.js web；不排除它就会被当成目标杀掉。
    String[] starters = {
      "sh " + LAUNCH + " boot " + PAYLOAD,
      "unshare -m --propagation private sh " + LAUNCH + " boot " + PAYLOAD,
      "sh " + LAUNCH + " boot node --expose-internals "
          + "/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js web --port 3080"
    };
    for (String starter : starters) {
      assertFalse(starter, WebProcSel.looksLikeWeb(starter));
      assertFalse(starter, WebProcSel.maySignalWeb(starter));
      assertEquals(starter, "", WebProcSel.trialProfile(starter));
    }
  }

  // ---------------------------------------------------------------- 不误认

  @Test
  public void ordinaryCommandsAreNotStarters() {
    for (String command :
        new String[] {
          "grep chroot logfile",
          "cat /data/user/0/com.dsh.client/files/chroot/host-launch.sh",
          "vim host-launch.sh",
          "sh host-launch.sh boot",
          "sh /data/user/0/com.dsh.client/files/chroot/host-launch.sh.bak boot",
          "sh /data/user/0/com.dsh.client/files/chroot/other.sh boot",
          "node server.js",
          "com.dsh.client",
          ""
        })
      assertFalse(command, WebProcSel.isChrootStarter(command));
    assertFalse(WebProcSel.isChrootStarter(null));
  }

  @Test
  public void similarNamesDoNotBecomeStarters() {
    // 前缀相同、脚本名不同的路径不能被认出来；.bak / -old 之类的变体也不行。
    assertFalse(WebProcSel.isChrootStarter("sh /data/user/0/com.dsh.client/files/chroot/xhost-launch.sh"));
    assertFalse(WebProcSel.isChrootStarter("sh /data/user/0/com.dsh.client/files/chroot/host-launch.sh.bak"));
    assertFalse(WebProcSel.isChrootStarter("sh /data/user/0/com.dsh.client/files/chroot/host-launch"));
    assertTrue(WebProcSel.CHROOT_SCRIPTS.length >= 1);
    for (String name : WebProcSel.CHROOT_SCRIPTS) assertFalse(name.startsWith("/"));
  }

  @Test
  public void unknownSubcommandIsNotAStarter() {
    // 形状对不上就不是启动器：脚本路径对了，但后面跟的不是已知子命令。
    for (String value : new String[] {"", "boots", "boot2", "--help", "-x", "BOOT"}) {
      String command = ("sh " + LAUNCH + " " + value).trim();
      assertFalse(command, WebProcSel.isChrootStarter(command));
    }
    // 子命令后面只允许跟选项：裸词说明这是「读了同一份脚本、多传一个参数」的别的命令。
    assertFalse(WebProcSel.isChrootStarter("sh " + LAUNCH + " boot extra"));
    assertTrue(WebProcSel.isChrootStarter("sh " + LAUNCH + " boot --pidns 1"));
    // 已知子命令则认得出。
    for (String subcommand : WebProcSel.CHROOT_SUBCOMMANDS)
      assertTrue(subcommand, WebProcSel.isChrootStarter("sh " + LAUNCH + " " + subcommand));
  }

  @Test
  public void starterDetectionDoesNotWeakenExistingExclusions() {
    // 回归：老判据一条都不能因为新增 chroot 分支而放宽。
    assertFalse(WebProcSel.looksLikeWeb("libproot.so -r /rootfs /usr/local/bin/dsh web"));
    assertFalse(WebProcSel.looksLikeWeb("libproroot-runtime.so -r /rootfs"));
    assertFalse(WebProcSel.looksLikeWeb("proot -w /root"));
    assertFalse(WebProcSel.looksLikeWeb("node server.js"));
    assertTrue(
        WebProcSel.looksLikeWeb(
            "node --expose-internals "
                + "/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js web"));
  }

  @Test
  public void chrootGuestNodeIsStillTheSignalTarget() {
    // chroot 里 setpriv 降回应用 UID 之后，cmdline 就是普通 node 启动行 ——
    // 那才是唯一该被发信号的目标（宿主与它同 UID，杀得动）。
    String guest =
        "node --expose-internals "
            + "/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js web "
            + "--no-open --host 127.0.0.1 --port 3080";
    assertTrue(WebProcSel.looksLikeWeb(guest));
    assertTrue(WebProcSel.maySignalWeb(guest));
  }
}
