package com.deepseekharness.app.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 运行时选择的<b>唯一入口</b>：把「用户偏好 + 探测结论 + 三连败」折算成「这一次到底用谁」
 * （纯逻辑，不碰 Android API —— 断言在 JVM 单元测试里）。
 *
 * <p><b>三条原则，逐条对应实施计划 §2.1</b>：
 * <ol>
 *   <li><b>探测决定选择</b>：自动模式下选谁由 {@link ChrootProbe} 的结论决定，不由上一次启动
 *       是否失败决定。无 root 时结论里没有 chroot 这一档，于是不会有「先试一次 chroot 等它
 *       失败」的等待 —— 这是计划里点名的硬要求。</li>
 *   <li><b>手动强制优先</b>：用户选了 native 档就用 native 档，不再看探测结论；只在模式非法或
 *       该档不可用时才回落到自动结论，并且回落是<b>可见</b>的（{@link Decision#fallbackReason()}）。</li>
 *   <li><b>降级是有界的</b>：一次「运行时归因」失败只降<b>一级</b>（{@link #next}），到 proot
 *       就没有下一级；proot 是链条的终点，绝不存在从 proot 再降。</li>
 * </ol>
 *
 * <p><b>持久化降级为什么不在这里</b>：连续三次才持久化、以及「环境变化自动复位重选」需要跨进程
 * 状态和存储。这里只算<b>本次</b>该用谁；持久化由 {@code RuntimePreference} 那类带存储的协作者
 * 负责，而它必须调用本类的 {@link #ladderOf} 来保证阶梯与探测结论一致。
 */
public final class RuntimeSelection {

  /** 运行时 ID —— 与 {@code ContainerRuntime.id()} 一致，也是 SharedPreferences 里的值。 */
  public static final String CHROOT = "chroot";
  public static final String PROROOT = "proroot";
  public static final String PROOT = "proot";

  private RuntimeSelection() {}

  /** 用户偏好（设置页「运行时」四选一）。 */
  public enum Mode {
    /** 自动（默认）：由探测结论决定。 */
    AUTO(null),
    /** 强制 chroot；不可用时回落到自动结论并提示。 */
    CHROOT(RuntimeSelection.CHROOT),
    /** 强制 proroot。 */
    PROROOT(RuntimeSelection.PROROOT),
    /** 强制 proot（最稳，也最慢）。 */
    PROOT(RuntimeSelection.PROOT);

    private final String nativeTier;

    Mode(String nativeTier) {
      this.nativeTier = nativeTier;
    }

    /** 该模式直接指定的档；自动模式为 null。 */
    public String nativeTier() {
      return nativeTier;
    }

    public boolean automatic() {
      return nativeTier == null;
    }

    /** 存盘值 → 模式。未知/空/历史非法值一律回落自动（旧键值 proot/proroot 天然被识别）。 */
    public static Mode parse(String value) {
      if (value == null) return AUTO;
      return switch (value.trim().toLowerCase(Locale.ROOT)) {
        case RuntimeSelection.CHROOT -> Mode.CHROOT;
        case RuntimeSelection.PROROOT -> Mode.PROROOT;
        case RuntimeSelection.PROOT -> Mode.PROOT;
        default -> AUTO;
      };
    }

    public String stored() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /** 选择结论。 */
  public record Decision(String runtime, Mode mode, List<String> ladder, String fallbackReason) {

    public Decision {
      ladder = List.copyOf(ladder);
    }

    public boolean automatic() {
      return mode.automatic();
    }

    /** 用户选了 native 档但因为不可用被改掉了 —— 界面必须显式说一句，不能静默。 */
    public boolean overrodeUserChoice() {
      return !fallbackReason.isEmpty();
    }
  }

  // ==================================================================

  /** 自动结论：探测 + proroot 资产可用性 → chroot / proroot / proot。 */
  public static String automatic(ChrootProbe.Result probe, boolean prorootUsable) {
    return ChrootProbe.choose(probe, prorootUsable);
  }

  /** 本次可用的完整阶梯；CHROOT 档只在探测通过时出现。 */
  public static List<String> ladderOf(ChrootProbe.Result probe, boolean prorootUsable) {
    return ChrootProbe.automaticLadder(probe, prorootUsable);
  }

  /** 某档此刻是否可用（含探测/资产判定）。 */
  public static boolean usable(String tier, ChrootProbe.Result probe, boolean prorootUsable) {
    if (tier == null) return false;
    return ladderOf(probe, prorootUsable).contains(tier);
  }

  /**
   * 选谁。
   *
   * @param mode 用户偏好
   * @param probe 探测结论（可能是 {@link ChrootProbe.Result#unknown}）
   * @param prorootUsable proroot 五个 .so 是否就位可执行
   */
  public static Decision choose(Mode mode, ChrootProbe.Result probe, boolean prorootUsable) {
    Mode effective = mode == null ? Mode.AUTO : mode;
    List<String> ladder = ladderOf(probe, prorootUsable);
    String nativeTier = effective.nativeTier();
    if (nativeTier != null && ladder.contains(nativeTier))
      return new Decision(nativeTier, effective, nativeLadder(nativeTier, ladder), "");
    String automatic = automatic(probe, prorootUsable);
    String reason =
        nativeTier == null ? "" : "RUNTIME_CHOICE_UNAVAILABLE:" + nativeTier;
    return new Decision(automatic, effective, ladder, reason);
  }

  /**
   * 强制某档时的阶梯：只允许从这一档往下走，<b>不</b>允许往上跳回更好的档。
   * 用户选 proroot 时不该因为探测结论更好就被悄悄升成 chroot。
   */
  private static List<String> nativeLadder(String tier, List<String> ladder) {
    List<String> from = new ArrayList<>();
    boolean seen = false;
    for (String candidate : ladder) {
      if (candidate.equals(tier)) seen = true;
      if (seen) from.add(candidate);
    }
    if (from.isEmpty()) from.add(tier);
    return List.copyOf(from);
  }

  /**
   * 降一级。<b>只有</b>「运行时归因」的失败可以调用它，且到 proot 为止。
   *
   * @param current 当前档
   * @param probe 探测结论
   * @param prorootUsable proroot 资产可用性
   * @return 下一档；已经在最后一档（proot）或档位无法识别时返回空串，表示「无路可降」
   */
  public static String next(String current, ChrootProbe.Result probe, boolean prorootUsable) {
    if (current == null || current.isEmpty()) return "";
    List<String> ladder = ladderOf(probe, prorootUsable);
    int at = ladder.indexOf(current);
    if (at < 0 || at == ladder.size() - 1) return "";
    return ladder.get(at + 1);
  }

  /**
   * 降级后的新偏好。
   *
   * <p>自动模式：把结论钉到<b>降级后的那一档</b>（写成该档的强制值），这样下一次冷启动不会又先
   * 去试已经失败过的档 —— 但环境变化后 {@link #resetForEnvironmentChange} 会把它放回自动，
   * 重新按新结论选。
   */
  public static Mode downgraded(Mode mode, ChrootProbe.Result probe, boolean prorootUsable) {
    Mode effective = mode == null ? Mode.AUTO : mode;
    String from = choose(effective, probe, prorootUsable).runtime();
    String to = next(from, probe, prorootUsable);
    if (to.isEmpty()) return effective;
    return switch (to) {
      case CHROOT -> Mode.CHROOT;
      case PROROOT -> Mode.PROROOT;
      default -> Mode.PROOT;
    };
  }

  /**
   * 环境变化（su 授权撤销、KSU 更新、rootfs 重装）后是否该复位成自动。
   *
   * <p>只复位<b>由失败降级产生</b>的偏好；用户自己手选的档（{@link Decision#overrodeUserChoice()}
   * 为 false 且非自动）要保留 —— 计划里「用户手动强制选项优先」是硬要求。
   */
  public static boolean resetForEnvironmentChange(Mode mode, boolean downgradedByFailure) {
    if (mode == null || mode.automatic()) return false;
    return downgradedByFailure;
  }

  /** 这个字符串是不是三档之一（外部写入的值先过这里再信）。 */
  public static boolean known(String tier) {
    return CHROOT.equals(tier) || PROROOT.equals(tier) || PROOT.equals(tier);
  }

  /** 规范化历史/外部写入的值；不认识的一律当自动。 */
  public static String stored(Mode mode) {
    return (mode == null ? Mode.AUTO : mode).stored();
  }
}
