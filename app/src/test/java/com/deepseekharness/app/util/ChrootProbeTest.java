package com.deepseekharness.app.util;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 探测结论与选择判据的断言。
 *
 * <p>重点是三条「错了会很难查」的行为：fail-closed（报告缺项不许当通过）、无 root 时直接
 * proroot（不许出现试探 chroot 的路径）、以及 PID ns 的两个条件必须同时成立。
 */
public final class ChrootProbeTest {

  private static ChrootProbe.Result result(Map<String, Boolean> checks, Map<String, String> facts) {
    return new ChrootProbe.Result(true, "", checks, facts, Map.of(), 1_700_000_000_000L);
  }

  private static Map<String, Boolean> allPassing() {
    Map<String, Boolean> checks = new LinkedHashMap<>();
    for (ChrootProbe.Check check : ChrootProbe.Check.values()) checks.put(check.key(), true);
    return checks;
  }

  private static Map<String, Boolean> passingWithout(ChrootProbe.Check missing) {
    Map<String, Boolean> checks = allPassing();
    checks.put(missing.key(), false);
    return checks;
  }

  // ---------------------------------------------------------------- 解析

  @Test
  public void parsesScriptReportAndKeepsUnknownKeys() {
    String report =
        String.join(
            "\n",
            "check.root=yes",
            "check.unshare=yes",
            "check.chroot=yes",
            "check.setpriv=yes",
            "fact.pagesize=16384",
            "fact.selinux_before=u:r:su:s0",
            "fact.something_new=42",
            "exit.probe=0");
    ChrootProbe.Result parsed = ChrootProbe.parse(report, 7L);
    assertTrue(parsed.readable());
    assertTrue(ChrootProbe.chrootUsable(parsed));
    assertEquals("16384", parsed.fact(ChrootProbe.Fact.PAGESIZE));
    assertEquals("u:r:su:s0", parsed.fact(ChrootProbe.Fact.SELINUX_BEFORE));
    // 脚本以后加了新探测项，旧 APK 也要能完整读出来，而不是当成格式错误。
    assertEquals("42", parsed.facts().get("something_new"));
    assertEquals(Integer.valueOf(0), parsed.exits().get("probe"));
    assertEquals(7L, parsed.atMillis());
  }

  @Test
  public void onlyExplicitYesPasses() {
    // ok / true / 1 / 空 都不放行 —— 探测是 fail-closed 的。
    for (String value : List.of("ok", "true", "1", "YES ", "yes")) {
      ChrootProbe.Result parsed = ChrootProbe.parse("check.root=" + value, 0L);
      if (value.trim().equalsIgnoreCase("yes")) assertTrue(parsed.passed(ChrootProbe.Check.ROOT));
      else assertFalse(parsed.passed(ChrootProbe.Check.ROOT));
    }
    assertFalse(ChrootProbe.parse("check.root=", 0L).passed(ChrootProbe.Check.ROOT));
  }

  @Test
  public void unreadableOrJunkReportIsNotUsable() {
    assertFalse(ChrootProbe.chrootUsable(null));
    assertFalse(ChrootProbe.chrootUsable(ChrootProbe.parse(null, 0L)));
    assertFalse(ChrootProbe.chrootUsable(ChrootProbe.parse("   ", 0L)));
    assertFalse(ChrootProbe.chrootUsable(ChrootProbe.parse("随便一段话\n没有任何键值", 0L)));
    assertEquals("EMPTY_REPORT", ChrootProbe.parse("", 0L).detail());
    assertEquals("UNRECOGNIZED_REPORT", ChrootProbe.parse("hello", 0L).detail());
    assertEquals("probe-unreadable", ChrootProbe.Result.unknown("x").blocking());
  }

  // ---------------------------------------------------------------- 结论

  @Test
  public void allFourChecksRequired() {
    assertTrue(ChrootProbe.chrootUsable(result(allPassing(), Map.of())));
    for (ChrootProbe.Check check : ChrootProbe.Check.values()) {
      ChrootProbe.Result partial = result(passingWithout(check), Map.of());
      assertFalse("缺 " + check.key() + " 时必须不可用", ChrootProbe.chrootUsable(partial));
      assertEquals(check.key(), partial.blocking());
    }
    // 四项全缺时也要能报出完整原因，而不是只报第一个。
    assertEquals(
        "root+unshare+chroot+setpriv",
        result(
                Map.of(
                    "root", false, "unshare", false, "chroot", false, "setpriv", false),
                Map.of())
            .blocking());
  }

  @Test
  public void recordsNeverBlockOnlyInfluenceDefaults() {
    Map<String, Boolean> checks = allPassing();
    Map<String, String> facts = new LinkedHashMap<>();
    facts.put(ChrootProbe.Fact.PID_NS.key(), "no");
    facts.put(ChrootProbe.Fact.DEVPTS.key(), "bind-fallback");
    facts.put(ChrootProbe.Fact.TMPFS.key(), "no");
    facts.put(ChrootProbe.Fact.PAGESIZE.key(), "16384");
    ChrootProbe.Result probe = result(checks, facts);
    // devpts/tmpfs/PID ns 都不是硬判据：有一项不行不该丢掉一个可用运行时。
    assertTrue(ChrootProbe.chrootUsable(probe));
    assertEquals("", probe.blocking());
    assertEquals("16384", probe.fact(ChrootProbe.Fact.PAGESIZE));
    // 报告里也要看得见「没探测」与「未通过」的区别。
    assertTrue(ChrootProbe.report(probe).contains("tmpfs"));
  }

  @Test
  public void noRootNeverProducesChroot() {
    ChrootProbe.Result noRoot = result(passingWithout(ChrootProbe.Check.ROOT), Map.of());
    assertEquals(RuntimeSelection.PROROOT, ChrootProbe.choose(noRoot, true));
    assertEquals(RuntimeSelection.PROOT, ChrootProbe.choose(noRoot, false));
    // 无 root 时 chroot 这一档压根不在阶梯里 —— 调用方因此不会「先试一次等它失败」。
    assertEquals(
        List.of(RuntimeSelection.PROROOT, RuntimeSelection.PROOT),
        ChrootProbe.automaticLadder(noRoot, true));
    assertFalse(ChrootProbe.automaticLadder(noRoot, true).contains(RuntimeSelection.CHROOT));
  }

  @Test
  public void ladderIsAlwaysDeterministicAndEndsAtProot() {
    ChrootProbe.Result usable = result(allPassing(), Map.of());
    assertEquals(
        List.of(RuntimeSelection.CHROOT, RuntimeSelection.PROROOT, RuntimeSelection.PROOT),
        ChrootProbe.automaticLadder(usable, true));
    assertEquals(
        List.of(RuntimeSelection.CHROOT, RuntimeSelection.PROOT),
        ChrootProbe.automaticLadder(usable, false));
    assertEquals(
        List.of(RuntimeSelection.PROOT), ChrootProbe.automaticLadder(null, false));
    // proot 是终点：任何输入下它都在最后一档。
    for (List<String> ladder :
        List.of(
            ChrootProbe.automaticLadder(usable, true),
            ChrootProbe.automaticLadder(usable, false),
            ChrootProbe.automaticLadder(null, true),
            ChrootProbe.automaticLadder(null, false)))
      assertEquals(RuntimeSelection.PROOT, ladder.get(ladder.size() - 1));
  }

  // ---------------------------------------------------------------- PID ns

  @Test
  public void pidNamespaceNeedsBuildableAndRecycling() {
    Map<String, String> buildable = Map.of(ChrootProbe.Fact.PID_NS.key(), "yes");
    Map<String, String> recycled =
        Map.of(
            ChrootProbe.Fact.PID_NS.key(), "yes", ChrootProbe.Fact.PID_NS_RECYCLE.key(), "yes");
    Map<String, String> notBuildable = Map.of(ChrootProbe.Fact.PID_NS.key(), "no");
    assertFalse(ChrootProbe.pidNamespaceEnabled(result(allPassing(), Map.of())));
    assertFalse(ChrootProbe.pidNamespaceEnabled(result(allPassing(), buildable)));
    assertTrue(ChrootProbe.pidNamespaceEnabled(result(allPassing(), recycled)));
    assertFalse(ChrootProbe.pidNamespaceEnabled(result(allPassing(), notBuildable)));
    assertFalse(ChrootProbe.pidNamespaceEnabled(null));
    // 计划 §2.2 的「暂定关闭」就是这个默认值。
    assertFalse(ChrootProbe.pidNamespaceEnabled(ChrootProbe.Result.unknown("x")));
  }

  @Test
  public void bundledToyboxRequiredWhenAnyToolMissing() {
    assertTrue(ChrootProbe.needsBundledToybox(null));
    assertTrue(ChrootProbe.needsBundledToybox(ChrootProbe.Result.unknown("x")));
    assertFalse(ChrootProbe.needsBundledToybox(result(allPassing(), Map.of())));
    assertTrue(
        ChrootProbe.needsBundledToybox(
            result(passingWithout(ChrootProbe.Check.SETPRIV), Map.of())));
    assertTrue(
        ChrootProbe.needsBundledToybox(
            result(passingWithout(ChrootProbe.Check.UNSHARE), Map.of())));
  }

  // ---------------------------------------------------------------- 导出

  @Test
  public void jsonExportIsStableSortedAndEscaped() {
    Map<String, Boolean> checks = allPassing();
    checks.put("chroot", false);
    ChrootProbe.Result probe =
        new ChrootProbe.Result(
            true,
            "",
            checks,
            Map.of(ChrootProbe.Fact.SELINUX_BEFORE.key(), "u:r:su:s0 \"quoted\"\n下一行"),
            Map.of("probe", 1),
            42L);
    String json = ChrootProbe.toJson(probe);
    assertTrue(json.startsWith("{\n"));
    assertTrue(json.endsWith("}\n"));
    // 引号与换行都要转义，否则报告本身就不是合法 JSON。
    assertTrue(json.contains("\\\"quoted\\\""));
    assertTrue(json.contains("\\n"));
    assertFalse(json.contains("\"\"\""));
    // 键按字典序：同一份结论在不同机器上导出必须逐字节一致。
    List<String> keys = new java.util.ArrayList<>();
    for (String line : json.split("\n")) {
      String trimmed = line.trim();
      if (!trimmed.startsWith("\"")) continue;
      int close = trimmed.indexOf('"', 1);
      assertTrue("键必须成对引号: " + trimmed, close > 1);
      keys.add(trimmed.substring(1, close));
    }
    assertEquals(keys.size(), json.split("\n").length - 2);
    List<String> sorted = new java.util.ArrayList<>(keys);
    java.util.Collections.sort(sorted);
    assertEquals(sorted, keys);
    assertTrue(json.contains("\"choice\": \"proroot\""));
    assertTrue(json.contains("\"blocking\": \"chroot\""));
    assertFalse(json.contains("u:r:su:s0\n"));
  }

  @Test
  public void jsonAndTextNeverClaimChrootForUnknownProbe() {
    String json = ChrootProbe.toJson(null);
    assertTrue(json.contains("\"readable\": \"no\""));
    assertTrue(json.contains("\"chrootUsable\": \"no\""));
    assertTrue(json.contains("\"choice\": \"proot\""));
    assertTrue(json.contains("NO_RESULT"));
    String text = ChrootProbe.report(null);
    assertTrue(text.contains("选择：proot"));
    assertFalse(text.contains("chroot 可用：是"));
  }

  @Test
  public void textReportStatesChoiceAndGaps() {
    ChrootProbe.Result probe = result(passingWithout(ChrootProbe.Check.SETPRIV), Map.of());
    String text = ChrootProbe.report(probe);
    assertTrue(text.contains("chroot 可用：否"));
    assertTrue(text.contains("缺项：setpriv"));
    assertTrue(text.contains("选择：proroot"));
  }

  // ---------------------------------------------------------------- 结论保鲜

  private static final long NOW = 1_800_000_000_000L;

  private static ChrootProbe.Result at(long millis, boolean readable) {
    return new ChrootProbe.Result(readable, "", allPassing(), Map.of(), Map.of(), millis);
  }

  @Test
  public void freshReadableProbeIsTrusted() {
    assertTrue(ChrootProbe.trusted(at(NOW, true), NOW));
    assertTrue(ChrootProbe.trusted(at(NOW - ChrootProbe.MAX_AGE_MILLIS, true), NOW));
    assertFalse(ChrootProbe.shouldReprobe(at(NOW, true), NOW));
  }

  @Test
  public void staleOrTimelessOrFutureProbeIsNotTrusted() {
    assertFalse(ChrootProbe.trusted(at(NOW - ChrootProbe.MAX_AGE_MILLIS - 1, true), NOW));
    // 没有时间戳（0）说明来源不明，不能当有效结论。
    assertFalse(ChrootProbe.trusted(at(0, true), NOW));
    // 时间戳在未来：时钟被改过或文件被换过，两种都不该信任。
    assertFalse(ChrootProbe.trusted(at(NOW + 1, true), NOW));
    // 不可读的结论一律不信任，哪怕时间戳很新。
    assertFalse(ChrootProbe.trusted(at(NOW, false), NOW));
    assertFalse(ChrootProbe.trusted(null, NOW));
  }

  @Test
  public void shouldReprobeForEveryUntrustedCase() {
    for (ChrootProbe.Result untrusted :
        List.of(
            at(NOW - ChrootProbe.MAX_AGE_MILLIS - 1, true),
            at(0, true),
            at(NOW + 60_000, true),
            at(NOW, false),
            ChrootProbe.Result.unknown("x", NOW))) {
      assertTrue(ChrootProbe.shouldReprobe(untrusted, NOW));
    }
    assertFalse(ChrootProbe.shouldReprobe(at(NOW - 1000, true), NOW));
    // 从没跑过（unknown + 无可读内容）必须重跑。
    assertTrue(ChrootProbe.shouldReprobe(ChrootProbe.parse(null, 0L), NOW));
  }

  @Test
  public void trustedTextMatchesParseThenTrusted() {
    String report = "check.root=yes\ncheck.setpriv=yes";
    assertTrue(ChrootProbe.trustedText(report, NOW - 1000, NOW));
    assertFalse(ChrootProbe.trustedText(report, NOW - ChrootProbe.MAX_AGE_MILLIS - 1, NOW));
    assertFalse(ChrootProbe.trustedText("", NOW, NOW));
    assertFalse(ChrootProbe.trustedText(null, NOW, NOW));
    // 报告本身不可读（没有 check./fact. 行）时，时间戳再新也不算可信。
    assertFalse(ChrootProbe.trustedText("没有键值的一段话", NOW, NOW));
  }

  @Test
  public void maxAgeIsThirtyDays() {
    assertEquals(30L * 24 * 60 * 60 * 1000, ChrootProbe.MAX_AGE_MILLIS);
    assertEquals(256 * 1024, ChrootProbe.MAX_REPORT_BYTES);
  }

  // ---------------------------------------------------------------- 真实脚本输出

  /**
   * 设置页探测脚本（{@code assets/chroot/host-probe.sh}）的实际输出形状。
   *
   * <p>这份夹具的价值在于<b>契约</b>：脚本改了键名、App 改了判据，两边任意一侧漂移都会在
   * 这里断掉 —— 否则症状是「探测永远说 chroot 不可用」，而原因谁也看不出来。
   */
  private static final String SCRIPT_OUTPUT =
      String.join(
          "\n",
          "check.root=yes",
          "exit.root=0",
          "fact.app_uid=10234",
          "check.unshare=yes",
          "check.chroot=yes",
          "fact.rootfs_present=yes",
          "fact.rootfs_bash=yes",
          "fact.rootfs_owner=10234:10234",
          "check.setpriv=yes",
          "fact.pid_ns=yes",
          "fact.tmpfs=yes",
          "fact.devpts=yes",
          "fact.selinux_before=u:r:su:s0",
          "fact.pagesize=4096",
          "fact.tool_unshare=yes",
          "fact.tool_chroot=yes",
          "fact.tool_setpriv=yes",
          "fact.tool_mount=yes",
          "fact.tool_umount=yes",
          "fact.tool_nsenter=no",
          "fact.writable__root=yes",
          "fact.writable__root_.dsh=yes",
          "fact.probe_version=1");

  @Test
  public void parsesTheProbeScriptOutputEndToEnd() {
    ChrootProbe.Result result = ChrootProbe.parse(SCRIPT_OUTPUT, NOW);
    assertTrue(result.readable());
    assertTrue(ChrootProbe.chrootUsable(result));
    assertEquals("", result.blocking());
    assertTrue(ChrootProbe.trusted(result, NOW));
    assertEquals(RuntimeSelection.CHROOT, ChrootProbe.choose(result, true));
    // 记录项要能被读到，且不因为缺失而影响结论。
    assertEquals("u:r:su:s0", result.fact(ChrootProbe.Fact.SELINUX_BEFORE));
    assertEquals("4096", result.fact(ChrootProbe.Fact.PAGESIZE));
    assertEquals("yes", result.fact(ChrootProbe.Fact.TMPFS));
    // 只读探测不做进程回收测试 —— 该项必须缺席，于是 PID ns 保持关闭（计划 §2.2 的暂定值）。
    assertEquals("", result.fact(ChrootProbe.Fact.PID_NS_RECYCLE));
    assertTrue(ChrootProbe.pidNamespaceBuildable(result));
    assertFalse(ChrootProbe.pidNamespaceEnabled(result));
    // nsenter 缺失不影响 chroot 可用性（不是硬判据）。
    assertFalse(ChrootProbe.needsBundledToybox(result));
  }

  @Test
  public void missingHardCheckMakesTheScriptOutputUnusable() {
    // 脚本某一行没打出来（例如早期退出）：结论必须是「不可用」，不能乐观默认成通过。
    for (String key : List.of("check.root", "check.unshare", "check.chroot", "check.setpriv")) {
      String damaged = SCRIPT_OUTPUT.replace(key + "=yes", key + "=no");
      ChrootProbe.Result result = ChrootProbe.parse(damaged, NOW);
      assertFalse(key, ChrootProbe.chrootUsable(result));
      assertEquals(key.substring("check.".length()), result.blocking());
      assertEquals(RuntimeSelection.PROROOT, ChrootProbe.choose(result, true));
      assertTrue(ChrootProbe.needsBundledToybox(result));
    }
  }

  @Test
  public void scriptOutputWithoutSetprivNeverSelectsChroot() {
    // setpriv 缺 → 只能以 root 跑 dsh → 宿主停止链路失效，属于安全模型倒退，必须拦下。
    String damaged = SCRIPT_OUTPUT.replace("check.setpriv=yes", "check.setpriv=no");
    ChrootProbe.Result result = ChrootProbe.parse(damaged, NOW);
    assertFalse(ChrootProbe.chrootUsable(result));
    assertTrue(ChrootProbe.needsBundledToybox(result));
    String text = ChrootProbe.report(result);
    assertTrue(text.contains("缺项：setpriv"));
    assertTrue(text.contains("选择：proroot"));
  }
}
