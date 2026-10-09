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
}
