package com.deepseekharness.app.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * chroot 运行时的能力探测结论与「选谁」的<b>唯一判据</b>（纯逻辑，不碰 Android API —— 断言在
 * JVM 单元测试里）。
 *
 * <p><b>为什么要单独一个类</b>：实施计划 §2.1 的原则是「选谁由<b>能力探测</b>决定，不由启动失败
 * 决定」。旧实现把这件事压成了一个布尔开关（{@code RuntimeHostPorts.Settings.proroot}），
 * 只能表达「要 proroot / 要 proot」两种意图，探测结论本身根本没有落脚点 —— 于是「无 root 时
 * 直接 proroot，不做 chroot 尝试、不产生失败重试与等待」这条硬要求无处可写。收成一份之后：
 *
 * <ul>
 *   <li>探测结论是<b>可导出、可复核</b>的结构化记录（设置页「运行环境探测」直接跑它，
 *       不必先装环境、不必起 Web）；</li>
 *   <li>选择规则是<b>确定性</b>的：root + chroot 能力全过 → chroot；否则 proroot 可用 →
 *       proroot；否则 proot。无 root 时结论里压根不会出现「试 chroot」这一步；</li>
 *   <li>缺什么导致没选 chroot，是<b>可归因</b>的（{@link Result#blocking()}），不会退化成
 *       「反正没起来」。</li>
 * </ul>
 *
 * <p><b>判据为什么是这四项</b>：{@code root}、{@code unshare}、{@code chroot}、{@code setpriv}
 * 各自都<b>不可替代</b> ——
 * <ul>
 *   <li>没有 root：挂载与 chroot 都不可能（chroot 不需要 userns，但需要 CAP_SYS_ADMIN）；</li>
 *   <li>没有 mount ns：挂载会泄漏到全局命名空间，污染系统且卸载不干净，宁可不用；</li>
 *   <li>没有 chroot 本体（rootfs / 可执行 / chroot 工具任一缺失）：这就不用谈了；</li>
 *   <li>没有 setpriv：只能以 root 跑 dsh，而 root 进程宿主（app UID）<b>打不到信号</b> ——
 *       现有的「pid 文件 + 出生身份核验」停止链路会整条失效，属于安全模型倒退，不能放行。</li>
 * </ul>
 *
 * <p>其余项（PID ns、tmpfs、devpts、W^X 脚本、PAGESIZE、SELinux 域）只<b>记录不拦截</b>：
 * 它们要么有一键开关（PID ns），要么有等价回落（devpts 可退 bind），要么是诊断信息
 * （16K 页、su 域），拿它们否决 chroot 会平白丢掉一个可用运行时。
 */
public final class ChrootProbe {

  private ChrootProbe() {}

  /** 会改变结论的四项；其余项只进报告。 */
  public enum Check {
    ROOT,
    UNSHARE,
    CHROOT,
    SETPRIV;

    public String key() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /** 只记录不拦截的项；缺了它 chroot 照样能用，但会影响某个默认值或诊断结论。 */
  public enum Fact {
    TMPFS,
    DEVPTS,
    PID_NS,
    PID_NS_RECYCLE,
    SCRIPT_EXEC,
    PAGESIZE,
    SELINUX_BEFORE,
    SELINUX_AFTER,
    ROOTFS_OWNER,
    APP_UID;

    public String key() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /** 探测证据：结构化结论 + 可复核明细。{@code exitCode} 为 null 表示未跑（或跑不起来）。 */
  public record Result(
      boolean readable,
      String detail,
      Map<String, Boolean> checks,
      Map<String, String> facts,
      Map<String, Integer> exits,
      long atMillis) {

    public Result {
      checks = Map.copyOf(checks);
      facts = Map.copyOf(facts);
      exits = Map.copyOf(exits);
    }

    /** 没跑过、读不到、格式不对 —— 一律当成「探测未通过」，绝不乐观默认成可用。 */
    public static Result unknown(String detail, long now) {
      return new Result(false, detail, Map.of(), Map.of(), Map.of(), now);
    }

    public static Result unknown(String detail) {
      return unknown(detail, 0L);
    }

    public boolean passed(Check check) {
      return Boolean.TRUE.equals(checks.get(check.key()));
    }

    public String fact(Fact fact) {
      return facts.getOrDefault(fact.key(), "");
    }

    /** 缺哪一项导致 chroot 不可用；全过时返回空串。用于「为什么没选 chroot」的显式提示。 */
    public String blocking() {
      if (!readable) return "probe-unreadable";
      List<String> missing = new ArrayList<>();
      for (Check check : Check.values()) if (!passed(check)) missing.add(check.key());
      return String.join("+", missing);
    }
  }

  // ==================================================================
  // 结论

  /** 探测得到的 chroot 可用性。 */
  public static boolean chrootUsable(Result result) {
    if (result == null || !result.readable()) return false;
    for (Check check : Check.values()) if (!result.passed(check)) return false;
    return true;
  }

  /**
   * 确定性选择：chroot → proroot → proot。
   *
   * <p>无 root 时这里<b>直接</b>给出 proroot/proot，不会经过 chroot —— 调用方因此不需要
   * 「先试一次 chroot 等它失败」。
   */
  public static String choose(Result result, boolean prorootUsable) {
    if (chrootUsable(result)) return RuntimeSelection.CHROOT;
    return prorootUsable ? RuntimeSelection.PROROOT : RuntimeSelection.PROOT;
  }

  /** 自动模式下的降级阶梯：由探测结论决定，chroot 不可用时该档直接不存在。 */
  public static List<String> automaticLadder(Result result, boolean prorootUsable) {
    List<String> ladder = new ArrayList<>();
    if (chrootUsable(result)) ladder.add(RuntimeSelection.CHROOT);
    if (prorootUsable) ladder.add(RuntimeSelection.PROROOT);
    ladder.add(RuntimeSelection.PROOT);
    return List.copyOf(ladder);
  }

  /** PID ns 实测可建。 */
  public static boolean pidNamespaceBuildable(Result result) {
    return result != null && "yes".equalsIgnoreCase(result.fact(Fact.PID_NS));
  }

  /** 孤儿/僵尸回收实测通过。 */
  public static boolean pidNamespaceRecycles(Result result) {
    return result != null && "yes".equalsIgnoreCase(result.fact(Fact.PID_NS_RECYCLE));
  }

  /**
   * PID ns 该不该开（计划 §2.2：默认值由阶段 0.5 冒烟结论决定，暂定关闭）。
   *
   * <p>必须<b>两个条件同时成立</b>：可建，且孤儿回收实测通过。只看「可建」就开是危险的 ——
   * PID 1 不回收会让僵尸在容器里持续累积，这比少一层 PID 隔离严重得多。
   */
  public static boolean pidNamespaceEnabled(Result result) {
    return pidNamespaceBuildable(result) && pidNamespaceRecycles(result);
  }

  /** 是否需要随包静态 toybox：宿主缺 unshare/chroot/setpriv 任一，就得自带。 */
  public static boolean needsBundledToybox(Result result) {
    if (result == null || !result.readable()) return true;
    return !result.passed(Check.UNSHARE)
        || !result.passed(Check.CHROOT)
        || !result.passed(Check.SETPRIV);
  }

  // ==================================================================
  // 解析

  private static final String PREFIX_CHECK = "check.";
  private static final String PREFIX_FACT = "fact.";
  private static final String PREFIX_EXIT = "exit.";

  /**
   * 解析冒烟脚本导出的报告。
   *
   * <p>格式约定成一行一条 {@code key=value}：脚本写起来是纯 shell、人肉看是纯文本、机器读不用
   * 引 JSON 解析器。未知键<b>保留在 facts 里</b>而不是丢掉 —— 脚本以后加了新探测项，旧 APK 读
   * 到的报告仍然完整，只是不认识。
   */
  public static Result parse(String report, long atMillis) {
    if (report == null || report.isBlank()) return Result.unknown("EMPTY_REPORT", atMillis);
    Map<String, Boolean> checks = new LinkedHashMap<>();
    Map<String, String> facts = new LinkedHashMap<>();
    Map<String, Integer> exits = new LinkedHashMap<>();
    for (String raw : report.split("\r?\n")) {
      String line = raw.trim();
      int at = line.indexOf('=');
      if (at <= 0) continue;
      String key = line.substring(0, at).trim();
      String value = line.substring(at + 1).trim();
      if (key.startsWith(PREFIX_CHECK) && key.length() > PREFIX_CHECK.length()) {
        // 只有 yes 算通过：任何别的写法（ok/true/1/空）都不放行 —— 探测 fail-closed。
        checks.put(key.substring(PREFIX_CHECK.length()), "yes".equalsIgnoreCase(value));
      } else if (key.startsWith(PREFIX_EXIT) && key.length() > PREFIX_EXIT.length()) {
        Integer code = parseExit(value);
        if (code != null) exits.put(key.substring(PREFIX_EXIT.length()), code);
      } else if (key.startsWith(PREFIX_FACT) && key.length() > PREFIX_FACT.length()) {
        facts.put(key.substring(PREFIX_FACT.length()), value);
      }
    }
    if (checks.isEmpty() && facts.isEmpty()) return Result.unknown("UNRECOGNIZED_REPORT", atMillis);
    return new Result(true, "", checks, facts, exits, atMillis);
  }

  private static Integer parseExit(String value) {
    String text = value.trim();
    if (text.isEmpty()) return null;
    try {
      return Integer.valueOf(text);
    } catch (NumberFormatException notANumber) {
      return null;
    }
  }

  // ==================================================================
  // 导出

  /** 给人看的文本报告（设置页「运行环境探测」+ 诊断附件）。 */
  public static String report(Result result) {
    StringBuilder text = new StringBuilder();
    text.append("DSHA 运行环境探测").append('\n');
    if (result == null || !result.readable()) {
      text.append("结论：未通过").append('\n');
      text.append("原因：").append(result == null ? "NO_RESULT" : result.detail()).append('\n');
      text.append("选择：").append(RuntimeSelection.PROOT).append("（探测不可用时不做乐观假设）\n");
      return text.toString();
    }
    text.append("chroot 可用：").append(chrootUsable(result) ? "是" : "否").append('\n');
    if (!chrootUsable(result)) text.append("缺项：").append(result.blocking()).append('\n');
    text.append("选择：").append(choose(result, true)).append('\n');
    text.append("PID ns：")
        .append(pidNamespaceEnabled(result) ? "开启" : "关闭")
        .append(pidNamespaceBuildable(result) ? "（可建" : "（不可建")
        .append(pidNamespaceRecycles(result) ? "、回收通过）" : "、回收未验）")
        .append('\n');
    text.append('\n').append("-- 硬判据 --").append('\n');
    for (Check check : Check.values())
      text.append("  ").append(check.key()).append(": ").append(passedText(result, check)).append('\n');
    if (!result.exits().isEmpty()) {
      text.append('\n').append("-- 退出码 --").append('\n');
      for (Map.Entry<String, Integer> entry : result.exits().entrySet())
        text.append("  ").append(entry.getKey()).append('=').append(entry.getValue()).append('\n');
    }
    if (!result.facts().isEmpty()) {
      text.append('\n').append("-- 记录项 --").append('\n');
      for (Map.Entry<String, String> entry : result.facts().entrySet())
        text.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
    }
    return text.toString();
  }

  private static String passedText(Result result, Check check) {
    Boolean value = result.checks().get(check.key());
    if (value == null) return "未探测";
    return value ? "通过" : "未通过";
  }

  /** JSON 导出：键按字典序，值为可打印文本；报告进诊断附件，不放命令原文与用户数据。 */
  public static String toJson(Result result) {
    Map<String, String> flat = new LinkedHashMap<>();
    if (result == null) {
      flat.put("readable", "no");
      flat.put("chrootUsable", "no");
      flat.put("blocking", "NO_RESULT");
      flat.put("choice", RuntimeSelection.PROOT);
    } else {
      flat.put("readable", result.readable() ? "yes" : "no");
      flat.put("chrootUsable", chrootUsable(result) ? "yes" : "no");
      flat.put("blocking", result.blocking());
      flat.put("choice", choose(result, true));
      flat.put("pidNamespace", pidNamespaceEnabled(result) ? "on" : "off");
      flat.put("atMillis", String.valueOf(result.atMillis()));
      for (Check check : Check.values())
        flat.put("check." + check.key(), passedText(result, check));
      for (Map.Entry<String, Integer> entry : result.exits().entrySet())
        flat.put("exit." + entry.getKey(), String.valueOf(entry.getValue()));
      for (Map.Entry<String, String> entry : result.facts().entrySet())
        flat.put("fact." + entry.getKey(), entry.getValue());
    }
    List<String> keys = new ArrayList<>(flat.keySet());
    Collections.sort(keys);
    StringBuilder json = new StringBuilder("{\n");
    for (int i = 0; i < keys.size(); i++) {
      json.append("  \"")
          .append(escape(keys.get(i)))
          .append("\": \"")
          .append(escape(flat.get(keys.get(i))))
          .append('"');
      if (i < keys.size() - 1) json.append(',');
      json.append('\n');
    }
    return json.append("}\n").toString();
  }

  private static String escape(String value) {
    StringBuilder out = new StringBuilder(value.length() + 8);
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
          else out.append(c);
        }
      }
    }
    return out.toString();
  }
}
