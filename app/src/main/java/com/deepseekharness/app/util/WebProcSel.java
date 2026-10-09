package com.deepseekharness.app.util;

/**
 * 「哪些进程算 Web 进程、怎么把它们找出来」的<b>唯一定义</b>（纯逻辑，不碰 Android API ——
 * 断言在 JVM 单元测试里）。
 *
 * <p><b>为什么要单独一个类</b>：停止功能已经改坏过三轮，每一轮的病根都在「判据」上，
 * 而判据当时散在四个地方各写一遍 —— 容器内的停止脚本、看门狗脚本、兜底杀、Android 侧扫
 * {@code /proc}。改一处漏三处，症状还都长得一样（点了停止没反应 / 停了又复活），
 * 极难分辨是哪一层没生效。收成一份之后，「该匹配什么」变成可以写断言钉住的东西：
 *
 * <ul>
 *   <li>真机上 dsh 的实际 cmdline（{@code node --expose-internals
 *       /usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js web}）必须被认出来；</li>
 *   <li>容器启动器（{@code libproot.so} / {@code libproroot}）<b>绝不能</b>被认成目标：
 *       杀到它等于把整个环境连 App 一起带走；</li>
 *   <li>用户自己或 agent 跑的 node 进程<b>不能</b>被误杀（曾经用 {@code pkill -f node}）。</li>
 * </ul>
 */
public final class WebProcSel {

  private WebProcSel() {}

  /**
   * 「用户已停止」哨兵（容器内路径）。存在即表示：<b>任何容器内的自动拉起路径都必须放弃</b>。
   *
   * <p>App 侧的判据管不到容器里的拉起者 —— 看门狗和它写的重启脚本是独立的 bash 进程。
   * 停止时只要漏杀一个，它下一轮就把 WebUI 拽回来，用户看到的正是<b>「停止之后 dsh 秒复活」</b>。
   * 哨兵不赌：拉起者每轮自己检查，看见就退出。删除点只有一处 —— 用户明确要启动的时候。
   */
  public static final String STOP_SENTINEL = "/root/.dsha-stopped";

  /** 端口的 {@code /proc/net/tcp} 表示（大写十六进制、补到 4 位）。 */
  public static String portHex(int port) {
    return String.format(java.util.Locale.ROOT, "%04X", port & 0xFFFF);
  }

  /**
   * Web 进程自己写下的 pid 文件（容器内路径）。
   *
   * <p><b>为什么必须有它</b>：前两版停止都在「按 cmdline 找进程」这条路上打转，而那条路
   * 有两个环境性的硬限制，在这台机器上实测确认过：
   * <ul>
   *   <li>{@code /proc/net/tcp} 对非 root App <b>读不到</b>（Permission denied，
   *       Android 10+ 收紧了 /proc/net）—— 所以 {@code ss}/{@code netstat}/端口反查
   *       全都只能拿到空结果，而且是<b>静默</b>的空；</li>
   *   <li>{@code /proc} 只看得到<b>同 uid</b> 的进程（Android 的 hidepid）。</li>
   * </ul>
   *
   * <p>pid 文件绕开这两条：启动方就是我们自己，{@code exec} 之前把 {@code $$} 写下来 ——
   * 因为 {@code exec} 用 node 顶替当前 shell、<b>pid 不变</b>，这个数就是 node 的 pid。
   * 停止时直接按 pid 杀，不猜命令行长相、不依赖任何工具。
   */
  public static final String PID_WEB = "/root/.dsha-web.pid";

  public static final String IDENTITY_WEB = "/root/.dsha-web.identity";

  /** 看门狗自己写下的 pid 文件（容器内路径）。 */
  public static final String PID_WATCHDOG = "/root/.dsha-watchdog.pid";

  // ---------------------------------------------------------------- chroot 启动器

  /**
   * chroot 运行时的宿主脚本名（{@code app/src/main/java/.../runtime/ChrootRuntime} 装配时使用）。
   *
   * <p>chroot 与 proot/proroot 有一个本质差别：它不是「一个可执行文件带一堆参数」，而是
   * <b>一条特权引导链</b>（{@code unshare → mount → chroot → setpriv}）。这条链的父进程以 root
   * 运行，宿主（app UID）<b>打不到它的信号</b>；而它的 argv 里带着整条待执行命令 —— 也就是说，
   * 对 {@code dsh web} 的<b>文本</b>匹配会在它身上命中。
   *
   * <p>所以这里和「绝不误杀 proot/proroot」是同一条规则：<b>认得出、且永远不当目标</b>。
   * 区别在于识别判据必须更严 —— 启动器 argv 的形状是固定的，只认完全对得上的那几种，
   * 不做子串匹配（否则用户自己 {@code grepping chroot} 也会被当成启动器）。
   */
  public static final String[] CHROOT_SCRIPTS = {
    "host-launch.sh", "host-ctl.sh", "host-ns-enter.sh"
  };

  /**
   * chroot 脚本的子命令；必须紧跟在脚本路径后面。
   *
   * <p>这一项是「认得出」与「不误认」的分界线：{@code cat host-launch.sh}、{@code vim …}、
   * {@code grep …} 的参数位置也满足「绝对路径 + 已知脚本名」，但它们后面跟的不是子命令。
   * 加上这一条之后，只有真正按启动器形状调用的进程才会被认出来。
   */
  public static final String[] CHROOT_SUBCOMMANDS = {
    "boot", "start", "stop", "status", "restart", "teardown", "probe"
  };

  /** 出现在脚本路径之前、允许被跳过的启动前置命令（它们自己不改变 argv 语义）。 */
  private static final java.util.Set<String> LAUNCH_PREFIXES =
      java.util.Set.of("unshare", "nsenter", "setsid", "toybox", "busybox");

  /**
   * 这条命令行是不是<b>本次 chroot 启动链</b>的某一环。
   *
   * <p>认两种形状，都是「完全对得上」而不是子串匹配：
   * <ol>
   *   <li><b>su 包装</b>（Java 侧实际用的）：
   *       {@code su -c 'sh "$0" boot' <绝对路径>/<已知脚本名>} ——
   *       脚本路径是独立 argv，所以路径里的奇怪字符不会影响判定；</li>
   *   <li><b>直接执行</b>（手工诊断 / 阶段 0.5 用）：
   *       {@code [unshare|nsenter|setsid…] [选项] <解释器|脚本本身> <已知脚本路径> <已知子命令> [--选项…]}。</li>
   * </ol>
   *
   * <p>其余一律 false —— 宁可漏认（退化成「当普通未知进程处理」，那本来也是 fail-closed），
   * 也不能把用户自己的进程认成启动器：{@code cat}/{@code vim}/{@code grep} 拿脚本当参数的
   * 情形都必须排除。
   */
  public static boolean isChrootStarter(String cmdline) {
    if (cmdline == null || cmdline.isEmpty()) return false;
    return isSuWrappedStarter(splitCmdline(cmdline)) || isDirectStarter(splitCmdline(cmdline));
  }

  /** {@code su -c 'sh "$0" boot' <脚本路径>}：路径是独立 argv，无需解析引号。 */
  private static boolean isSuWrappedStarter(String[] argv) {
    if (argv.length != 4) return false;
    if (!basename(argv[0]).equals("su")) return false;
    if (!argv[1].equals("-c")) return false;
    if (!isChrootLaunchSnippet(argv[2])) return false;
    return isChrootScriptPath(argv[3]);
  }

  /** 与 {@code ContainerRuntime.Chroot.GUEST_LAUNCH} 同一条，允许空白差异。 */
  static boolean isChrootLaunchSnippet(String snippet) {
    if (snippet == null) return false;
    return snippet.trim().replaceAll("\\s+", " ").equals("sh \"$0\" boot");
  }

  /** 直接执行：{@code [前缀命令…] <解释器|脚本> <脚本路径> <子命令> [--选项…]}。 */
  private static boolean isDirectStarter(String[] argv) {
    int at = 0;
    while (at < argv.length && isLaunchPrefix(basename(argv[at]))) {
      at++;
      at = skipOptions(argv, at);
    }
    if (at >= argv.length) return false;
    if (!isShell(basename(argv[at]))) {
      // 允许直接 exec 脚本本身（内核用 shebang 接管），此时形状要与解释器分支一致。
      return isChrootScriptPath(argv[at]) && isStarterTail(argv, at);
    }
    return at + 1 < argv.length && isChrootScriptPath(argv[at + 1]) && isStarterTail(argv, at + 1);
  }

  /** 脚本路径之后必须是已知子命令，且子命令后面只允许跟选项（以及选项的值）。 */
  private static boolean isStarterTail(String[] argv, int scriptAt) {
    int subcommandAt = scriptAt + 1;
    if (subcommandAt >= argv.length || !isChrootSubcommand(argv[subcommandAt])) return false;
    return skipOptions(argv, subcommandAt + 1) == argv.length;
  }

  /**
   * 跳过一段选项，返回第一个非选项元素的下标。
   *
   * <p>{@code --long} 后面可能跟一个值（{@code --propagation private}、{@code --pidns 1}），
   * 而 <b>option-with-value 形式的裸词正是子命令之后不该出现的东西</b> —— 所以只在紧跟在
   * {@code --} 选项之后时才把一个裸词当值吞掉，别处的裸词一律留着当「形状不对」。
   */
  private static int skipOptions(String[] argv, int from) {
    int at = from;
    while (at < argv.length) {
      String argument = argv[at];
      if (argument.startsWith("--")) {
        at++;
        if (at < argv.length && !argv[at].startsWith("-")) at++;
        continue;
      }
      if (argument.startsWith("-") && argument.length() > 1) {
        at++;
        continue;
      }
      break;
    }
    return at;
  }

  /** 某一个 argv 元素是不是本项目的 chroot 脚本路径（必须是绝对路径 + 已知脚本名）。 */
  static boolean isChrootScriptPath(String argument) {
    if (argument == null || argument.isEmpty() || argument.charAt(0) != '/') return false;
    int slash = argument.lastIndexOf('/');
    if (slash < 0 || slash == argument.length() - 1) return false;
    String name = argument.substring(slash + 1);
    for (String known : CHROOT_SCRIPTS) if (known.equals(name)) return true;
    return false;
  }

  private static boolean isChrootSubcommand(String argument) {
    for (String known : CHROOT_SUBCOMMANDS) if (known.equals(argument)) return true;
    return false;
  }

  private static boolean isLaunchPrefix(String executable) {
    return LAUNCH_PREFIXES.contains(executable);
  }

  /** 引导链只通过这些解释器拉起脚本；{@code cat}/{@code vim}/{@code grep} 一律不算。 */
  private static boolean isShell(String executable) {
    return executable.equals("sh")
        || executable.equals("ash")
        || executable.equals("bash")
        || executable.equals("mksh");
  }

  /** argv 切分：有 NUL 按 NUL，否则按空白（与其余判据一致）。 */
  private static String[] splitCmdline(String cmdline) {
    return cmdline.indexOf('\0') >= 0
        ? cmdline.split("\u0000")
        : cmdline.trim().split("\\s+");
  }

  /** PID 文件只接受单个正整数；拒绝 PID 1、进程组及任何 shell 语法。 */
  public static int parsePid(String value) {
    if (value == null || value.length() > 32) return -1;
    String digits = value.trim();
    if (!digits.matches("[1-9][0-9]{0,9}")) return -1;
    try {
      int pid = Integer.parseInt(digits);
      return pid > 1 ? pid : -1;
    } catch (NumberFormatException ignored) {
      return -1;
    }
  }

  /** pid 文件相对 rootfs 根的路径 —— Android 侧要用 {@code File} 直接读它。 */
  public static String pidFileRel(String guestPath) {
    return guestPath.startsWith("/") ? guestPath.substring(1) : guestPath;
  }

  /**
   * Android 侧判据：这条 cmdline 该不该被当作「Web 进程」杀掉。
   *
   * <p>顺序有意义：<b>先排除容器启动器</b>，再匹配目标。反过来写的话，
   * proot 的命令行里带着 rootfs 路径与待执行命令，{@code bin.js}、{@code web}
   * 都可能出现在里面 —— 于是第一个被杀的就是承载整个环境的那个进程。
   */
  public static boolean looksLikeWeb(String cmdline) {
    if (cmdline == null || cmdline.isEmpty()) return false;
    // chroot 的引导链带着整条待执行命令，文本里必然出现 "dsh web" —— 先排除它，
    // 与下面排除 proot/proroot 的理由完全相同：它不是目标，是承载目标的那个东西。
    if (isChrootStarter(cmdline)) return false;
    // proroot 的 bridge 是 guest 可执行程序本身，父进程 libproroot.so 才是启动器。
    // 只接受已知的 Node + dsh web 参数序列，不能因命令中带有 bridge 名称就放行。
    String[] argv = splitCmdline(cmdline);
    if (argv.length > 0 && basename(argv[0]).equals("libproroot-bridge.so"))
      return isProrootWebPayload(argv) || isProrootManagedWebShell(argv);
    if (argv.length == 0) return false;
    String executable = basename(argv[0]);
    if (executable.equals("libproot.so")
        || executable.startsWith("libproroot")
        || executable.equals("proot")) return false;
    if (maySignalWeb(cmdline)) return true;
    // Exact executable script positions only; grep/vim/echo and shell -c text are not processes we
    // own.
    if ((executable.equals("bash") || executable.equals("sh")) && argv.length > 1) {
      // The app's pre-exec shell is still a writer/startup owner. Recognize its exact
      // generation+PID+sentinel contract for the barrier, but never signal this shell by name.
      if (argv.length == 3 && argv[1].equals("-c") && managedWebShell(argv[2])) return true;
      return argv[1].equals("/root/dsh-watchdog.sh")
          || argv[1].equals("/root/dsh-web-restart.sh")
          || argv[1].equals("/root/dsh-cmd.txt");
    }
    if (!isNode(argv[0]) || argv.length < 3) return false;
    int entry = argv[1].equals("--expose-internals") ? 2 : 1;
    if (entry + 1 >= argv.length) return false;
    return (argv[entry].endsWith("/node_modules/@deepseek-ai/dsh-app-boot/lib/bin.js")
            || argv[entry].endsWith("/node_modules/@deepseek-ai/dsh-cli/lib/bin.js"))
        && webArguments(argv, entry + 1);
  }

  private static boolean managedWebShell(String command) {
    return command.startsWith("export DSH_HOME=/root/.dsh && ")
        && command.contains("export DSHA_STARTUP_PROFILE=")
        && command.contains("export DSHA_WEB_GENERATION=")
        && command.contains("echo $$ > " + PID_WEB)
        && command.contains("[ ! -e " + STOP_SENTINEL + " ] || exit 0;")
        && (command.contains("exec dsh web --no-open --host 127.0.0.1 --port ")
            || command.contains("exec dsh --profile 'dsha-recovery-"));
  }

  private static boolean isProrootManagedWebShell(String[] argv) {
    return argv.length == 9
        && basename(argv[1]).equals("libproroot-linker.so")
        && argv[2].equals("--argv0")
        && basename(argv[3]).equals("bash")
        && argv[4].equals("--preload")
        && basename(argv[5]).equals("libproroot-runtime.so")
        && argv[6].endsWith("/bin/bash")
        && argv[7].equals("-c")
        && managedWebShell(argv[8]);
  }

  private static boolean isProrootWebPayload(String[] argv) {
    if (argv.length < 9
        || !basename(argv[1]).equals("libproroot-linker.so")
        || !argv[2].equals("--argv0")
        || !isNode(argv[3])
        || !argv[4].equals("--preload")
        || !basename(argv[5]).equals("libproroot-runtime.so")
        || !isManagedNode(argv[6])) return false;
    int entry = 7;
    if (argv[entry].equals("--expose-internals")) entry++;
    if (entry + 1 >= argv.length) return false;
    return (argv[entry].equals("/usr/local/bin/dsh")
            || argv[entry].equals("/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js"))
        && webArguments(argv, entry + 1);
  }

  private static String basename(String path) {
    return path.substring(path.lastIndexOf('/') + 1);
  }

  private static boolean isNode(String path) {
    String name = basename(path);
    return name.equals("node") || name.equals("nodejs");
  }

  private static boolean isManagedNode(String path) {
    return path.endsWith("/usr/local/bin/node") || path.endsWith("/usr/local/bin/nodejs");
  }

  /** 发信号须是直接运行 dsh web 的 Node，不能命中 shell 参数中的文本。 */
  public static boolean maySignalWeb(String cmdline) {
    if (cmdline == null || cmdline.isEmpty()) return false;
    // chroot 启动链以 root 运行：宿主即使认出来也杀不动它，而且它承载着整个环境。
    // 这里明确说不 —— 「能识别」不等于「可以杀」。
    if (isChrootStarter(cmdline)) return false;
    String[] args = splitCmdline(cmdline);
    if (args.length > 0 && basename(args[0]).equals("libproroot-bridge.so"))
      return isProrootWebPayload(args);
    if (args.length < 3 || !isNode(args[0])) return false;
    int entry = args[1].equals("--expose-internals") ? 2 : 1;
    if (entry + 1 >= args.length) return false;
    return (args[entry].equals("/usr/local/bin/dsh")
            || args[entry].endsWith("/node_modules/@deepseek-ai/dsh/lib/bin.js"))
        && webArguments(args, entry + 1);
  }

  /** 返回严格直启命令绑定的隔离 profile；普通 Web、shell 包装和伪造参数均为空。 */
  public static String trialProfile(String cmdline) {
    if (cmdline == null || cmdline.isEmpty()) return "";
    // chroot 启动链会带 profile 参数，但它不是「直启 Web」—— 试运行隔离不适用于它。
    if (isChrootStarter(cmdline)) return "";
    String[] args = splitCmdline(cmdline);
    int argument;
    if (args.length > 0 && basename(args[0]).equals("libproroot-bridge.so")) {
      if (!isProrootWebPayload(args)) return "";
      int entry = 7;
      if (args[entry].equals("--expose-internals")) entry++;
      argument = entry + 1;
    } else {
      if (args.length < 3 || !isNode(args[0])) return "";
      int entry = args[1].equals("--expose-internals") ? 2 : 1;
      if (entry + 1 >= args.length
          || !(args[entry].equals("/usr/local/bin/dsh")
              || args[entry].endsWith("/node_modules/@deepseek-ai/dsh/lib/bin.js"))) return "";
      argument = entry + 1;
    }
    if (argument + 1 >= args.length || !args[argument].equals("--profile")) return "";
    String profile = args[argument + 1];
    return profile.matches("dsha-recovery-[0-9a-f]{16}") ? profile : "";
  }

  private static boolean webArguments(String[] args, int index) {
    return args[index].equals("web")
        || (index + 1 < args.length
            && args[index].equals("--profile")
            && args[index + 1].matches(
                "(?:dsha-recovery-[0-9a-f]{16}|dsha-emergency-[0-9a-f]{32})"));
  }
}
