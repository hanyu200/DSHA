package com.deepseekharness.app.runtime;

import android.content.Context;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器运行时抽象：把「怎么进 rootfs 执行命令」独立出来，让 chroot / proroot / proot 并存、可切换。
 *
 * <p>三条实现：
 * <ul>
 *   <li>{@link Proot} —— Termux 的 proot（APK 内置 libproot.so），天然兜底；</li>
 *   <li>{@link Proroot} —— coderredlab/proroot，LD_PRELOAD + 二进制补丁，零 ptrace 开销；</li>
 *   <li>{@link Chroot} —— 内核级 chroot + 挂载命名空间，需要 root，无翻译层。</li>
 * </ul>
 *
 * <p><b>chroot 与另外两条的本质差别</b>（决定了下面两个新增的契约）：
 * <ol>
 *   <li>它不是「一个可执行文件带一串参数」，而是一条<b>特权引导链</b>
 *       （{@code unshare → mount → chroot → setpriv}），必须经 {@code su} 拉起。
 *       于是「进 rootfs 的 argv」不再等于「启动器 argv」——由 {@link #hostShell()} 描述。</li>
 *   <li>它的 bind 是把宿主路径挂到 rootfs 内（{@code mount --bind host $R/guest}），
 *       不是启动器的 {@code -b} 参数 —— 由 {@link #bindsThroughLauncher()} 区分。</li>
 * </ol>
 *
 * <p>proroot 的 argv 里<b>没有</b> {@code --kill-on-exit}：{@code Process.destroy()} 只杀启动器，
 * 容器里的 node 会变孤儿继续跑 —— 所以「停止」必须按 pid 精确杀（见 {@code WebProcSel}），
 * 不能指望杀启动器传播信号。chroot 同样如此（还多一层 root 域），所以它的监护进程被刻意
 * 设计成降回应用 UID 运行，让宿主那条「pid 文件 + 出生身份核验」链路原样可用。
 */
public interface ContainerRuntime {

  String id();

  String displayName();

  boolean available();

  String unavailableReason();

  /** 组装进入 rootfs 的命令前缀（不含最终要跑的 guest shell 命令）。 */
  List<String> baseArgv(File rootfsDir, boolean hardlinkSupported);

  /** Null dataDomain is an explicit independent rescue domain, never inferred from rootfs parents. */
  List<String> baseArgv(File rootfsDir, boolean hardlinkSupported, File dataDomain);

  /** 设置进程环境（LD_LIBRARY_PATH、TMPDIR 之类）。 */
  void applyEnv(ProcessBuilder pb, File baseDir, File libDir, File tmpDir)
      throws java.io.IOException;

  /** 首次使用前的准备。抛异常表示失败，调用方应回退。 */
  void prepare() throws Exception;

  // ==================================================================
  // chroot 需要的两个额外契约（其余实现给默认值，行为一字不变）

  /** 环境变量的施加方式。 */
  enum EnvMode {
    /** proot/proroot：LD_LIBRARY_PATH / PROOT_* / PROROOT_* 之类由启动器读取。 */
    LAUNCHER,
    /** chroot：宿主侧只有 su / unshare 这些工具，环境变量由引导脚本自己摆进 guest。 */
    HOST_SCRIPT
  }

  default EnvMode envMode() {
    return EnvMode.LAUNCHER;
  }

  /**
   * {@code baseArgv} 返回的是不是「宿主可执行文件 + 参数」，后面直接跟 guest shell 命令。
   *
   * <p>proot/proroot 是：启动器跑完就直接在容器里执行 {@code /bin/bash -c <cmd>}。
   * chroot 不是：它的 argv 被 su 吃掉，guest 命令要经环境变量传给引导脚本。
   */
  default boolean appendsGuestCommand() {
    return true;
  }

  /**
   * {@code LaunchSpec} 里的额外 bind 是否由启动器参数表达（{@code -b host:guest}）。
   * chroot 为 false —— 它的 bind 由引导脚本做 {@code mount --bind}。
   */
  default boolean bindsThroughLauncher() {
    return true;
  }

  /** 进 rootfs 的最终 argv 形态：宿主可执行文件 + 参数前缀。 */
  record HostShell(String executable, List<String> prefix) {
    public HostShell {
      prefix = List.copyOf(prefix);
    }

    /** 拼出完整 argv：前缀 + 调用方给的尾部（guest 命令或脚本子命令）。 */
    public List<String> argv(String... tail) {
      List<String> argv = new ArrayList<>(prefix.size() + tail.length + 1);
      argv.add(executable);
      argv.addAll(prefix);
      argv.addAll(List.of(tail));
      return argv;
    }

    public boolean usable() {
      return executable != null && !executable.isEmpty();
    }
  }

  /**
   * 进 rootfs 的宿主侧 argv 前缀。
   *
   * <p>默认实现保持老行为：{@code baseArgv} 的全部内容就是启动器 argv，后面由
   * {@code RuntimeLauncher} 追加 {@code /bin/bash -c <command>}。
   */
  default HostShell hostShell(File rootfsDir, boolean hardlinkSupported, File dataDomain) {
    List<String> argv = baseArgv(rootfsDir, hardlinkSupported, dataDomain);
    if (argv.isEmpty()) return new HostShell("", List.of());
    return new HostShell(argv.get(0), argv.subList(1, argv.size()));
  }

  // ==================================================================

  /** Termux proot，APK 内置。 */
  class Proot implements ContainerRuntime {
    private final File nativeLibProot;
    private final Context context;
    private final RuntimeHostPorts.Settings explicitSettings;

    public Proot(Context ctx, File nativeLibProot) {
      this(ctx, nativeLibProot, null);
    }

    public Proot(Context ctx, File nativeLibProot, RuntimeHostPorts.Settings settings) {
      this.nativeLibProot = nativeLibProot;
      this.context = ctx;
      this.explicitSettings = settings;
    }

    @Override
    public String id() {
      return "proot";
    }

    @Override
    public String displayName() {
      return com.deepseekharness.app.util.UiText.text("proot（内置，稳定）");
    }

    @Override
    public boolean available() {
      return nativeLibProot != null && nativeLibProot.isFile() && nativeLibProot.length() > 0;
    }

    @Override
    public String unavailableReason() {
      return available()
          ? ""
          : com.deepseekharness.app.util.UiText.text("APK 内的 libproot.so 缺失（安装包可能损坏，建议重装）");
    }

    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported) {
      if (context == null) throw new IllegalStateException("DATA_DOMAIN_CONTEXT_MISSING");
      return baseArgv(rootfsDir, hardlinkSupported, context.getFilesDir());
    }

    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported, File dataDomain) {
      List<String> argv = new ArrayList<>();
      argv.add(nativeLibProot.getAbsolutePath());
      // 只有文件系统不支持硬链接时才需要 link2symlink 模拟（会破坏 dsh write 工具）。
      // Android app 私有目录（/data/…，ext4/f2fs）本来就支持硬链接，扩展纯属多余。
      if (!hardlinkSupported) {
        argv.add("--link2symlink");
        // L2S 链保存宿主绝对路径，容器必须能按同一路径访问，否则 dpkg 的 chown/stat 报 ENOENT。
        File l2s = new File(rootfsDir, ".l2s");
        l2s.mkdirs();
        argv.add("-b");
        argv.add(l2s.getAbsolutePath() + ":" + l2s.getAbsolutePath());
      }
      argv.add("-L");
      argv.add("--kill-on-exit");
      argv.add("-0");
      argv.add("--rootfs=" + rootfsDir.getAbsolutePath());
      argv.add("--cwd=/root");
      for (Bind b : binds()) {
        if (!new File(b.host()).exists()) {
          if (context != null)
            RuntimeHostPorts.fromOwner(context.getApplicationContext())
                .record("BIND_SKIPPED", b.host() + ": missing or inaccessible");
          continue;
        }
        argv.add("-b");
        argv.add(b.host().equals(b.guest()) ? b.host() : b.host() + ":" + b.guest());
      }
      if (dataDomain != null) UserDataBindings.append(argv, rootfsDir, dataDomain);
      return argv;
    }

    @Override
    public void applyEnv(ProcessBuilder pb, File baseDir, File libDir, File tmpDir)
        throws java.io.IOException {
      prepare();
      File directory = nativeLibProot.getParentFile();
      String loader =
          nativeLibProot.getName().equals("libproot_legacy.so")
              ? "libprootloader_legacy.so"
              : "libprootloader.so";
      if (!new File(libDir, "libtalloc.so.2").isFile()
          || !new File(libDir, "libandroid-shmem.so").isFile())
        throw new java.io.IOException("PROOT_DEPENDENCIES_MISSING");
      RuntimeHostPorts.Settings settings =
          explicitSettings == null
              ? RuntimeHostPorts.fromOwner(context.getApplicationContext()).settings()
              : explicitSettings;
      if (settings.disableProotSeccomp) pb.environment().put("PROOT_NO_SECCOMP", "1");
      else pb.environment().remove("PROOT_NO_SECCOMP");
      pb.environment().put("PROOT_TMP_DIR", tmpDir.getAbsolutePath());
      pb.environment().put("PROOT_LOADER", new File(directory, loader).getAbsolutePath());
      File loader32 = new File(directory, "libprootloader32.so");
      if (loader32.isFile()) pb.environment().put("PROOT_LOADER_32", loader32.getAbsolutePath());
      else pb.environment().remove("PROOT_LOADER_32");
      pb.environment()
          .put("LD_LIBRARY_PATH", libDir.getAbsolutePath() + ":" + directory.getAbsolutePath());
    }

    @Override
    public void prepare() throws java.io.IOException {
      if (!available()) throw new java.io.IOException("PROOT_EXECUTABLE_MISSING");
      String loader =
          nativeLibProot.getName().equals("libproot_legacy.so")
              ? "libprootloader_legacy.so"
              : "libprootloader.so";
      if (!new File(nativeLibProot.getParentFile(), loader).isFile())
        throw new java.io.IOException("PROOT_LOADER_MISSING");
    }
  }

  /** coderredlab/proroot，LD_PRELOAD 路径翻译，零 ptrace。 */
  class Proroot implements ContainerRuntime {
    /** 五个 .so 都得在同一目录，启动器靠 /proc/self/exe 的 dirname 找同伴。 */
    public static final String[] LIBS = {
      "libproroot.so",
      "libproroot-runtime.so",
      "libproroot-linker.so",
      "libproroot-stub-loader.so",
      "libproroot-bridge.so",
    };

    private final Context ctx;
    private final File dir;
    private final boolean staticLoader;

    public Proroot(Context ctx, File dir) {
      this(
          ctx,
          dir,
          RuntimeHostPorts.fromOwner(ctx.getApplicationContext()).settings().staticLoader);
    }

    public Proroot(Context ctx, File dir, boolean staticLoader) {
      this.ctx = ctx;
      this.dir = dir;
      this.staticLoader = staticLoader;
    }

    /**
     * 存放目录：APK 的 jniLibs 提取目录（nativeLibraryDir）。
     * <b>不能放 filesDir</b>：Android 10+ 的 W^X 策略不允许从应用可写目录执行代码。
     */
    public static File defaultDir(Context ctx) {
      return new File(ctx.getApplicationInfo().nativeLibraryDir);
    }

    @Override
    public String id() {
      return "proroot";
    }

    @Override
    public String displayName() {
      return com.deepseekharness.app.util.UiText.text("proroot（实验，零 ptrace 开销）");
    }

    @Override
    public boolean available() {
      for (String n : LIBS) {
        File f = new File(dir, n);
        if (!f.isFile() || f.length() == 0) return false;
      }
      return true;
    }

    @Override
    public String unavailableReason() {
      List<String> missing = new ArrayList<>();
      for (String n : LIBS) {
        File f = new File(dir, n);
        if (!f.isFile() || f.length() == 0) missing.add(n);
      }
      if (missing.isEmpty()) return "";
      return com.deepseekharness.app.util.UiText.format(
          "缺 %s 个运行时文件（%s 等）", missing.size(), missing.get(0));
    }

    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported) {
      return baseArgv(rootfsDir, hardlinkSupported, ctx.getFilesDir());
    }

    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported, File dataDomain) {
      List<String> argv = new ArrayList<>();
      argv.add(new File(dir, "libproroot.so").getAbsolutePath());
      argv.add(staticLoader ? "--static-loader" : "--no-static-loader");
      argv.add("-r");
      argv.add(rootfsDir.getAbsolutePath());
      argv.add("-0");
      argv.add("-w");
      argv.add("/root");
      for (Bind b : binds()) {
        if (!new File(b.host()).exists()) {
          RuntimeHostPorts.fromOwner(ctx.getApplicationContext())
              .record("BIND_SKIPPED", b.host() + ": missing or inaccessible");
          continue;
        }
        argv.add("-b");
        argv.add(b.host() + ":" + b.guest());
      }
      File shm = shmDir();
      //noinspection ResultOfMethodCallIgnored
      shm.mkdirs();
      argv.add("-b");
      argv.add(shm.getAbsolutePath() + ":/dev/shm");
      argv.add("--link2symlink");
      if (dataDomain != null) UserDataBindings.append(argv, rootfsDir, dataDomain);
      return argv;
    }

    File shmDir() {
      return new File(ctx.getCacheDir(), "shm");
    }

    @Override
    public void applyEnv(ProcessBuilder pb, File baseDir, File libDir, File tmpDir) {
      pb.environment().put("PROROOT_TMP_DIR", tmpDir.getAbsolutePath());
      pb.environment()
          .put("PROROOT_LIB_PATH", new File(dir, "libproroot-runtime.so").getAbsolutePath());
      pb.environment()
          .put("PROROOT_LINKER_PATH", new File(dir, "libproroot-linker.so").getAbsolutePath());
      if (staticLoader)
        pb.environment()
            .put(
                "PROROOT_STUB_LOADER",
                new File(dir, "libproroot-stub-loader.so").getAbsolutePath());
      else pb.environment().remove("PROROOT_STUB_LOADER");
    }

    @Override
    public void prepare() throws Exception {
      for (String n : LIBS) {
        if (!new File(dir, n).isFile()) {
          throw new IllegalStateException(
              com.deepseekharness.app.util.UiText.format("proroot 运行时缺 %s", n));
        }
      }
      //noinspection ResultOfMethodCallIgnored
      shmDir().mkdirs();
    }
  }

  /**
   * 内核级 chroot + 挂载命名空间。需要 root（不依赖 userns），零翻译层。
   *
   * <p>与另外两条实现的三处结构性差异，全部体现在覆写的方法上：
   * <ol>
   *   <li>{@link #hostShell} —— 宿主侧 argv 是 {@code su -c "sh <引导脚本> boot"}，
   *       guest 命令经环境变量 { code DSHA_CHROOT_COMMAND} 传给脚本；</li>
   *   <li>{@link #appendsGuestCommand()} 返回 false —— 不能再往 argv 后面拼
   *       {@code /bin/bash -c <cmd>}（那会被 su 当成自己的参数）；</li>
   *   <li>{@link #bindsThroughLauncher()} 返回 false —— bind 由引导脚本做
   *       {@code mount --bind}，不是启动器的 {@code -b} 参数。</li>
   * </ol>
   *
   * <p><b>权限模型</b>：{@code setpriv} 只改 UID/GID，<b>不改 SELinux 上下文</b> ——
   * guest 会以 AppUid + su 域（如 {@code u:r:su:s0}）运行，权限面比上游的 app 域宽。
   * 这是已知差异，写进安全模型文档，不做「看起来更安全」的假声明。
   */
  class Chroot implements ContainerRuntime {
    private final Context context;
    private final File hostScripts;
    private final File script;
    private final int appUid, appGid;
    private final File pidFile, sentinelFile, envFile, logFile, readyFile;

    /**
     * @param hostScripts {@code ChrootHostScripts.prepare()} 出来的目录（内容摘要编号）
     * @param script 引导脚本绝对路径（{@code hostScripts/host-launch.sh}）
     */
    public Chroot(
        Context context,
        File hostScripts,
        File script,
        int appUid,
        int appGid,
        File pidFile,
        File sentinelFile,
        File envFile,
        File logFile,
        File readyFile) {
      this.context = context;
      this.hostScripts = hostScripts;
      this.script = script;
      this.appUid = appUid;
      this.appGid = appGid;
      this.pidFile = pidFile;
      this.sentinelFile = sentinelFile;
      this.envFile = envFile;
      this.logFile = logFile;
      this.readyFile = readyFile;
    }

    @Override
    public String id() {
      return com.deepseekharness.app.util.RuntimeSelection.CHROOT;
    }

    @Override
    public String displayName() {
      return com.deepseekharness.app.util.UiText.text("chroot（需 root，无翻译层）");
    }

    @Override
    public boolean available() {
      return script != null && script.isFile() && script.length() > 0;
    }

    @Override
    public String unavailableReason() {
      return available()
          ? ""
          : com.deepseekharness.app.util.UiText.text("chroot 引导脚本缺失（重新安装或修复环境）");
    }

    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported) {
      return baseArgv(rootfsDir, hardlinkSupported, context.getFilesDir());
    }

    /**
     * chroot 不走「启动器 + 参数」这套，返回空表；真正要跑的东西见 {@link #hostShell}。
     *
     * <p>刻意不在这里返回 su 的 argv：那会让 {@code RuntimeLauncher} 以为后面还要跟
     * guest 命令，从而拼出被 su 吃掉的参数。形态由 {@link #hostShell} 一家说了算。
     */
    @Override
    public List<String> baseArgv(File rootfsDir, boolean hardlinkSupported, File dataDomain) {
      return List.of();
    }

    /**
     * {@code su -c 'sh "$0" boot' <脚本绝对路径>}。
     *
     * <p>为什么把脚本路径<b>作为独立 argv</b>追加、而不是拼进 {@code -c} 字符串：
     * <ul>
     *   <li>{@code su -c} 的字符串会<b>再经一层 shell 解析</b>，往里拼路径就多一层引号要
     *       照顾 —— 而这正是仓库里已经栽过跟头的那类错误；</li>
     *   <li>用 {@code "$0"} 取它，路径里的空格、引号、{@code $} 全部按字面量传递，
     *       不需要任何转义。</li>
     * </ul>
     * 这也是 {@code WebProcSel} 认启动链时依赖的确切形状。
     */
    @Override
    public HostShell hostShell(File rootfsDir, boolean hardlinkSupported, File dataDomain) {
      return new HostShell("su", List.of("-c", GUEST_LAUNCH, script.getAbsolutePath()));
    }

    /** 引导脚本的引导片段：{@code $0} 由调用方以独立 argv 提供。 */
    static final String GUEST_LAUNCH = "sh \"$0\" boot";

    @Override
    public EnvMode envMode() {
      return EnvMode.HOST_SCRIPT;
    }

    @Override
    public boolean appendsGuestCommand() {
      return false;
    }

    @Override
    public boolean bindsThroughLauncher() {
      return false;
    }

    /**
     * chroot 的宿主侧环境：su / unshare 这些工具不需要 LD_LIBRARY_PATH，也不需要
     * PROOT_*；这里只摆引导脚本要读的那几项，并清掉可能干扰的 proot/proroot 变量。
     */
    @Override
    public void applyEnv(ProcessBuilder pb, File baseDir, File libDir, File tmpDir) {
      var env = pb.environment();
      env.remove("PROOT_TMP_DIR");
      env.remove("PROOT_LOADER");
      env.remove("PROOT_LOADER_32");
      env.remove("PROOT_NO_SECCOMP");
      env.remove("PROOT_L2S_DIR");
      env.remove("PROROOT_TMP_DIR");
      env.remove("PROROOT_LIB_PATH");
      env.remove("PROROOT_LINKER_PATH");
      env.remove("PROROOT_STUB_LOADER");
      env.remove("LD_LIBRARY_PATH");
      env.put("DSHA_CHROOT_SCRIPT", script.getAbsolutePath());
      env.put("DSHA_CHROOT_APP_UID", String.valueOf(appUid));
      env.put("DSHA_CHROOT_APP_GID", String.valueOf(appGid));
      env.put("DSHA_CHROOT_PIDFILE", pidFile.getAbsolutePath());
      env.put("DSHA_CHROOT_SENTINEL", sentinelFile.getAbsolutePath());
      if (envFile != null) env.put("DSHA_CHROOT_ENVFILE", envFile.getAbsolutePath());
      if (logFile != null) env.put("DSHA_CHROOT_LOGFILE", logFile.getAbsolutePath());
      if (readyFile != null) env.put("DSHA_CHROOT_READYFILE", readyFile.getAbsolutePath());
      env.put("DSHA_CHROOT_PIDNS", "0");
    }

    /** guest 命令与额外 bind 由 {@code RuntimeLauncher} 调用这两个方法传入。 */
    public void putCommand(ProcessBuilder pb, String command) {
      pb.environment().put("DSHA_CHROOT_COMMAND", command == null ? "" : command);
    }

    public void putBinds(ProcessBuilder pb, List<Bind> binds) {
      StringBuilder text = new StringBuilder();
      for (Bind bind : binds) {
        if (bind == null || bind.host() == null || bind.guest() == null) continue;
        if (bind.host().indexOf('\n') >= 0 || bind.guest().indexOf('\n') >= 0) continue;
        text.append(bind.host()).append(':').append(bind.guest()).append('\n');
      }
      pb.environment().put("DSHA_CHROOT_BINDS", text.toString());
    }

    @Override
    public void prepare() throws Exception {
      if (!available())
        throw new IllegalStateException(
            com.deepseekharness.app.util.UiText.text("chroot 引导脚本缺失"));
      if (pidFile == null || sentinelFile == null)
        throw new IllegalStateException("CHROOT_PATHS_MISSING");
      File parent = pidFile.getParentFile();
      if (parent != null && !parent.isDirectory() && !parent.mkdirs())
        throw new IllegalStateException("CHROOT_PID_DIRECTORY");
    }

    /** 引导脚本目录（诊断用；内容摘要即目录名）。 */
    File hostScripts() {
      return hostScripts;
    }
  }

  /** POSIX 单引号转义；复用 {@code ShellQuote} 保证与仓库其它地方同一条规则。 */
  static String quote(String value) {
    return com.deepseekharness.app.util.ShellQuote.arg(value);
  }

  /**
   * 两个运行时共用的 bind 列表，写在一处（避免「改了 proot 忘了改 proroot」）。
   * Bundled Termux Python 要用 Android 的 linker 和 APEX 库，所以映射 /system、/apex。
   *
   * <p>注意：<b>不</b>映射 /linkerconfig —— app 进程对它无权限（selinux），
   * proot 每次启动都会打 {@code can't sanitize binding "/linkerconfig": Permission denied}，
   * 污染终端/日志；而且 bind 失败 = 从没绑上，映射它是纯负收益。
   */
  record Bind(String host, String guest) {}

  static java.util.List<Bind> binds() {
    return java.util.List.of(
        new Bind("/dev", "/dev"),
        new Bind("/dev/urandom", "/dev/random"),
        new Bind("/proc", "/proc"),
        new Bind("/sys", "/sys"),
        new Bind("/system", "/system"),
        new Bind("/apex", "/apex"),
        new Bind("/proc/self/fd", "/dev/fd"),
        new Bind("/storage/emulated/0", "/sdcard"),
        new Bind("/storage/emulated/0", "/storage/emulated/0"));
  }
}
