package com.deepseekharness.app.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * 「这次启动失败该不该换运行时」的<b>唯一判据</b>（纯逻辑，不碰 Android API —— 断言在 JVM
 * 单元测试里）。
 *
 * <p><b>为什么要有它</b>：实施计划 §2.1 的失败兜底是<b>例外路径</b>，只对「运行时归因」的失败
 * 开放。区分这两类不是谨慎，而是正确性 —— 把应用层错误当运行时错误会导致：
 * <ul>
 *   <li>用户配错端口 / 插件崩溃 / dsh 自身报错，被记成「chroot 不行」，于是无缘无故降级到更慢
 *       的运行时，真正的病根永远没被修；</li>
 *   <li>连续三次把应用层错误算进「三连败」，把可用环境持久化降级掉。</li>
 * </ul>
 *
 * <p><b>默认是「不降级」</b>：只有能明确对上运行时层签名（su 拒绝 / 挂载失败 / chroot exec
 * 失败 / 内核与装载器错误）才放行；其余一律同档重试上报错。这与仓库既有的
 * {@link WebRuntimeFallback}（proroot 在鉴权前明确退出才允许重试一次）是同一条思路，
 * 只是把「明确退出」换成了「明确签名」。
 *
 * <p><b>为什么按签名而不是按退出码</b>：退出码在这里几乎无区分度 —— node 未捕获异常、插件
 * 崩溃、端口占用都可能给出 1；而 126/127 在 shell 语义里既可能是运行时缺工具，也可能是用户
 * 脚本写错路径。反过来，内核和装载器给的信号很干净（ENOENT 找不到加载器、EPERM/EACCES 被拒、
 * 段错误 139），这些<b>只可能</b>来自运行时层。
 */
public final class RuntimeFallback {

  private RuntimeFallback() {}

  /** 归因结论。 */
  public enum Attribution {
    /** 与运行时层无关（应用层错误）：同档报错，绝不降级。 */
    APPLICATION,
    /** 运行时层错误：允许本次尝试降一级。 */
    RUNTIME,
    /** 证据不足以归因：按「不降级」处理 —— 宁可让用户看到真实报错。 */
    UNKNOWN
  }

  /** 已知的运行时错误签名：{@code 正则} + 归因。 */
  private record Signature(Pattern pattern, Attribution attribution) {}

  private static final List<Signature> SIGNATURES = List.of(
      // ---------------- shell / 工具层：运行时入口根本没跑起来 ----------------
      sig("\\bcan't execute\\b", Attribution.RUNTIME),
      sig("\\bcannot execute\\b", Attribution.RUNTIME),
      sig("\\bPermission denied\\b", Attribution.RUNTIME),
      sig("\\bOperation not permitted\\b", Attribution.RUNTIME),
      sig("\\bNo such file or directory\\b", Attribution.RUNTIME),
      sig("\\bnot found\\b", Attribution.RUNTIME),
      sig("\\bExec format error\\b", Attribution.RUNTIME),
      sig("\\bText file busy\\b", Attribution.RUNTIME),

      // ---------------- 挂载 / 命名空间链 ----------------
      sig("\\bmount: ", Attribution.RUNTIME),
      sig("\\bumount: ", Attribution.RUNTIME),
      sig("\\bunshare: ", Attribution.RUNTIME),
      sig("\\bchroot: ", Attribution.RUNTIME),
      sig("\\bnsenter: ", Attribution.RUNTIME),
      sig("\\bsetpriv: ", Attribution.RUNTIME),
      sig("\\bfailed to set up mount namespace\\b", Attribution.RUNTIME),
      sig("\\bMount namespace.*(failed|denied)\\b", Attribution.RUNTIME),
      sig("\\bmounting .* failed\\b", Attribution.RUNTIME),
      sig("\\bRead-only file system\\b", Attribution.RUNTIME),

      // ---------------- su 层 ----------------
      sig("(?i)\\bsu: (?:access denied|permission denied|not allowed|denied)\\b",
          Attribution.RUNTIME),
      sig("(?i)\\baccess denied\\b", Attribution.RUNTIME),
      sig("(?i)\\broot (?:access )?(?:denied|unavailable)\\b", Attribution.RUNTIME),
      sig("(?i)\\bno root\\b", Attribution.RUNTIME),

      // ---------------- SELinux ----------------
      sig("(?i)\\bavc: +denied\\b", Attribution.RUNTIME),
      sig("(?i)\\bSELinux\\b.*\\b(denied|blocked)\\b", Attribution.RUNTIME),

      // ---------------- 内核 / 装载器 ----------------
      sig("(?i)\\bSIGSEGV\\b", Attribution.RUNTIME),
      sig("(?i)\\bSIGABRT\\b", Attribution.RUNTIME),
      sig("(?i)\\bsegmentation fault\\b", Attribution.RUNTIME),
      sig("(?i)\\bBus error\\b", Attribution.RUNTIME),
      sig("(?i)\\bIllegal instruction\\b", Attribution.RUNTIME),
      sig("(?i)\\bKilled\\b", Attribution.RUNTIME),
      sig("(?i)\\bproot error\\b", Attribution.RUNTIME),
      sig("(?i)\\bproroot\\b.*\\b(error|failed|missing)\\b", Attribution.RUNTIME),
      // 缺 .so 的两种写法：missing 在前（"missing libtalloc.so.2"）或在后
      // （"libproroot-runtime.so: missing"）—— 两个方向都要认，否则漏判会变成「同档重试到死」。
      sig("(?i)\\bmissing\\s+\\S*\\.so(\\.[0-9]+)*\\b", Attribution.RUNTIME),
      sig("(?i)\\S*\\.so(\\.[0-9]+)*\\s*:\\s*missing\\b", Attribution.RUNTIME),
      // 动态装载器的两种报法都要认：so-name 在冒号前（大小写混合的库名如 libproroot-runtime.so），
      // 或者经典的 "error while loading shared libraries"。
      sig("(?i)\\bcannot open shared object file\\b", Attribution.RUNTIME),
      sig("(?i)\\berror while loading shared libraries\\b", Attribution.RUNTIME),

      // ---------------- 宿主侧已有的运行时错误码 ----------------
      sig("\\bRUNTIME_SELECTION_FALLBACK\\b", Attribution.RUNTIME),
      sig("\\bPROOT_[A-Z_]+\\b", Attribution.RUNTIME),
      sig("\\bPROROOT_[A-Z_]+\\b", Attribution.RUNTIME),
      sig("\\bBOUNDED_PROROOT_SESSION_UNAVAILABLE\\b", Attribution.RUNTIME),
      sig("\\bNATIVE_LIBRARY_PREPARATION_FAILED\\b", Attribution.RUNTIME),

      // ---------------- 应用层：显式排除，任何情况下都不降级 ----------------
      sig("(?i)\\bEADDRINUSE\\b|\\baddress already in use\\b|\\bport .* in use\\b",
          Attribution.APPLICATION),
      sig("(?i)\\binvalid (?:api )?key\\b|\\b401 unauthorized\\b|\\b403 forbidden\\b",
          Attribution.APPLICATION),
      sig("(?i)\\bplugin\\b.*\\b(?:error|failed|crash|invalid)\\b", Attribution.APPLICATION),
      sig("(?i)\\b(?:config|configuration|settings)\\b.*\\b(?:invalid|error|missing)\\b",
          Attribution.APPLICATION),
      sig("(?i)\\bTypeError\\b|\\bReferenceError\\b|\\bSyntaxError\\b", Attribution.APPLICATION),
      // Node 的未捕获拒绝有两种写法（带空格 / camelCase），都要算应用层。
      sig("(?i)\\bunhandled ?(?:promise ?)?rejection\\b", Attribution.APPLICATION),
      sig("(?i)\\bfailed to parse\\b|\\bmalformed\\b", Attribution.APPLICATION),
      sig("(?i)\\bEACCES\\b.*\\b(?:plugin|config)\\b", Attribution.APPLICATION),
      sig("(?i)\\bno such plugin\\b", Attribution.APPLICATION));

  /** 运行时层的内核错误码；{@code null} 表示不是信号。 */
  private static final int SIGSEGV = 139;
  private static final int SIGABRT = 134;
  private static final int SIGBUS = 135;
  private static final int SIGILL = 132;

  /**
   * 归因。
   *
   * <p>顺序有意义：<b>先看应用层签名</b>，再看运行时签名。一条输出里同时出现两类签名时
   * （例如插件崩了之后 shell 打了一句 "not found"），按应用层处理 —— 少降一级的代价是慢，
   * 多降一级的代价是把环境搞坏。
   *
   * @param output 启动输出（stdout/stderr 合并后的文本，可为 null）
   * @param exitCode 已确认的退出码；null 表示进程没退出或退出结果未确认
   */
  public static Attribution attribute(String output, Integer exitCode) {
    String text = output == null ? "" : output;
    List<Attribution> hits = new ArrayList<>();
    for (Signature signature : SIGNATURES)
      if (signature.pattern().matcher(text).find()) hits.add(signature.attribution());
    if (hits.contains(Attribution.APPLICATION)) return Attribution.APPLICATION;
    if (hits.contains(Attribution.RUNTIME)) return Attribution.RUNTIME;
    // 终止信号是内核给的，只可能来自运行时层（或 dsh 自己崩，那种情况下列举不出应用层签名，
    // 同档重试一次也不会造成「环境整体降级」之外的损害；连续三次才会持久化）。
    if (exitCode != null
        && (exitCode == SIGSEGV || exitCode == SIGABRT || exitCode == SIGBUS
            || exitCode == SIGILL)) return Attribution.RUNTIME;
    return Attribution.UNKNOWN;
  }

  /** 只有明确归因到运行时层才允许本次降级。 */
  public static boolean mayDowngrade(String output, Integer exitCode) {
    return attribute(output, exitCode) == Attribution.RUNTIME;
  }

  /** 是不是终止信号（用于诊断文案，不参与决策）。 */
  public static boolean terminatedBySignal(Integer exitCode) {
    if (exitCode == null) return false;
    return exitCode == SIGSEGV || exitCode == SIGABRT || exitCode == SIGBUS || exitCode == SIGILL;
  }

  /** 归因结果的中文解释，用于「显式提示」里的原因行。 */
  public static String describe(Attribution attribution) {
    return switch (attribution) {
      case RUNTIME -> "运行时层错误（su / 挂载 / chroot 执行 / 内核与装载器）";
      case APPLICATION -> "应用层错误（dsh / 插件 / 端口 / 配置），不降级";
      case UNKNOWN -> "原因未确认，按不降级处理";
    };
  }

  private static Signature sig(String regex, Attribution attribution) {
    return new Signature(Pattern.compile(regex), attribution);
  }

  /** 诊断用：把输出裁到有界长度，避免把整份日志塞进报告。 */
  public static String boundedEvidence(String output, int limit) {
    if (output == null) return "";
    String text = output.strip();
    if (text.length() <= limit) return text;
    int keep = Math.max(0, limit - 3);
    return text.substring(0, keep) + "...";
  }

  /** 归因结论的稳定 ID（进诊断与偏好，不随界面语言变化）。 */
  public static String code(Attribution attribution) {
    return attribution.name().toLowerCase(Locale.ROOT);
  }
}
