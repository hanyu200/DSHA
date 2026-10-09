package com.deepseekharness.app.util;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 选择阶梯的断言。
 *
 * <p>三条硬要求各有一组：探测决定选择（无 root 不试 chroot）、手动强制优先（不可用时回落且
 * 可见）、降级有界（一次一级，proot 是终点）。
 */
public final class RuntimeSelectionTest {

  private static ChrootProbe.Result probe(boolean chrootOk) {
    Map<String, Boolean> checks = new LinkedHashMap<>();
    for (ChrootProbe.Check check : ChrootProbe.Check.values()) checks.put(check.key(), chrootOk);
    return new ChrootProbe.Result(true, "", checks, Map.of(), Map.of(), 0L);
  }

  private static final ChrootProbe.Result USABLE = probe(true);
  private static final ChrootProbe.Result UNUSABLE = probe(false);

  // ---------------------------------------------------------------- 模式解析

  @Test
  public void parsesStoredValueAndUnknownFallsBackToAuto() {
    assertEquals(RuntimeSelection.Mode.AUTO, RuntimeSelection.Mode.parse(null));
    assertEquals(RuntimeSelection.Mode.AUTO, RuntimeSelection.Mode.parse(""));
    assertEquals(RuntimeSelection.Mode.AUTO, RuntimeSelection.Mode.parse("   "));
    assertEquals(RuntimeSelection.Mode.AUTO, RuntimeSelection.Mode.parse("whatever"));
    assertEquals(RuntimeSelection.Mode.PROOT, RuntimeSelection.Mode.parse("proot"));
    assertEquals(RuntimeSelection.Mode.PROROOT, RuntimeSelection.Mode.parse("proroot"));
    assertEquals(RuntimeSelection.Mode.CHROOT, RuntimeSelection.Mode.parse("CHROOT"));
    // 历史键值必须原样认得 —— 老用户存的是 proot / proroot。
    assertEquals(RuntimeSelection.Mode.PROROOT, RuntimeSelection.Mode.parse(" proroot "));
    assertEquals("auto", RuntimeSelection.Mode.AUTO.stored());
    assertEquals("chroot", RuntimeSelection.Mode.CHROOT.stored());
  }

  // ---------------------------------------------------------------- 自动

  @Test
  public void automaticFollowsProbeOnly() {
    assertEquals(RuntimeSelection.CHROOT, RuntimeSelection.automatic(USABLE, true));
    // 探测通过但 proroot 资产缺失不影响 chroot。
    assertEquals(RuntimeSelection.CHROOT, RuntimeSelection.automatic(USABLE, false));
    assertEquals(RuntimeSelection.PROROOT, RuntimeSelection.automatic(UNUSABLE, true));
    assertEquals(RuntimeSelection.PROOT, RuntimeSelection.automatic(UNUSABLE, false));
    assertEquals(RuntimeSelection.PROOT, RuntimeSelection.automatic(null, false));
    assertEquals(RuntimeSelection.PROROOT, RuntimeSelection.automatic(null, true));
  }

  @Test
  public void automaticNeverTriesChrootWhenProbeFailed() {
    // 计划 §2.1：无 root 时直接 proroot，不做 chroot 尝试、不产生失败重试与等待。
    // 表现就是 chroot 压根不在阶梯里 —— 调用方拿不到「先试 chroot」这个选项。
    RuntimeSelection.Decision decision =
        RuntimeSelection.choose(RuntimeSelection.Mode.AUTO, UNUSABLE, true);
    assertEquals(RuntimeSelection.PROROOT, decision.runtime());
    assertFalse(decision.ladder().contains(RuntimeSelection.CHROOT));
    assertEquals(List.of(RuntimeSelection.PROROOT, RuntimeSelection.PROOT), decision.ladder());
    assertFalse(decision.overrodeUserChoice());
  }

  // ---------------------------------------------------------------- 强制

  @Test
  public void explicitChoiceWinsWhenUsable() {
    for (RuntimeSelection.Mode mode :
        List.of(
            RuntimeSelection.Mode.CHROOT,
            RuntimeSelection.Mode.PROROOT,
            RuntimeSelection.Mode.PROOT)) {
      RuntimeSelection.Decision decision = RuntimeSelection.choose(mode, USABLE, true);
      assertEquals(mode.nativeTier(), decision.runtime());
      assertEquals("", decision.fallbackReason());
      assertFalse(decision.overrodeUserChoice());
    }
  }

  @Test
  public void explicitChoiceDoesNotUpgradeItself() {
    // 用户手选 proot（最稳）时，即使探测说 chroot 可用也不能被悄悄升上去。
    RuntimeSelection.Decision decision =
        RuntimeSelection.choose(RuntimeSelection.Mode.PROOT, USABLE, true);
    assertEquals(RuntimeSelection.PROOT, decision.runtime());
    assertEquals(List.of(RuntimeSelection.PROOT), decision.ladder());
    assertEquals("", RuntimeSelection.next(RuntimeSelection.PROOT, USABLE, true));
  }

  @Test
  public void explicitChoiceFallsBackVisiblyWhenUnavailable() {
    RuntimeSelection.Decision decision =
        RuntimeSelection.choose(RuntimeSelection.Mode.CHROOT, UNUSABLE, true);
    assertEquals(RuntimeSelection.PROROOT, decision.runtime());
    // 必须能被界面读出来「你选的这档不可用」—— 计划禁止静默降级。
    assertTrue(decision.overrodeUserChoice());
    assertEquals("RUNTIME_CHOICE_UNAVAILABLE:chroot", decision.fallbackReason());

    RuntimeSelection.Decision missingProroot =
        RuntimeSelection.choose(RuntimeSelection.Mode.PROROOT, UNUSABLE, false);
    assertEquals(RuntimeSelection.PROOT, missingProroot.runtime());
    assertEquals("RUNTIME_CHOICE_UNAVAILABLE:proroot", missingProroot.fallbackReason());
  }

  // ---------------------------------------------------------------- 降级

  @Test
  public void downgradeMovesExactlyOneStepAtATime() {
    assertEquals(RuntimeSelection.PROROOT, RuntimeSelection.next(RuntimeSelection.CHROOT, USABLE, true));
    assertEquals(RuntimeSelection.PROOT, RuntimeSelection.next(RuntimeSelection.PROROOT, USABLE, true));
    // proot 是终点，绝不存在从 proot 再降。
    assertEquals("", RuntimeSelection.next(RuntimeSelection.PROOT, USABLE, true));
    assertEquals("", RuntimeSelection.next("nonsense", USABLE, true));
    assertEquals("", RuntimeSelection.next(null, USABLE, true));
  }

  @Test
  public void downgradeFromChrootSkipsMissingProrootTier() {
    // proroot 资产缺失时，chroot 失败只能直接落到 proot，不能落到一个不存在的档。
    assertEquals(RuntimeSelection.PROOT, RuntimeSelection.next(RuntimeSelection.CHROOT, USABLE, false));
  }

  @Test
  public void downgradedModePinsTheNextTierDown() {
    assertEquals(
        RuntimeSelection.Mode.PROROOT,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.AUTO, USABLE, true));
    assertEquals(
        RuntimeSelection.Mode.PROOT,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.PROROOT, USABLE, true));
    // 已经在终点：保持原样，不能因为「降级」把用户的选择改成别的。
    assertEquals(
        RuntimeSelection.Mode.PROOT,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.PROOT, USABLE, true));
  }

  @Test
  public void downgradePinsTheTierBelowTheOneThatJustFailed() {
    // 探测未通过的机器上，「自动」的当前档就是 proroot；降一级就该钉到 proot。
    assertEquals(
        RuntimeSelection.Mode.PROOT,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.AUTO, UNUSABLE, true));
    // proroot 资产也缺失时当前档已经是 proot —— 已经在终点，没有可降的，偏好保持原样
    // （不能因为「降级」把用户的选择改成别的档）。
    assertEquals(
        RuntimeSelection.Mode.AUTO,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.AUTO, UNUSABLE, false));
    // 探测通过的机器上，自动档是 chroot，降一级钉到 proroot。
    assertEquals(
        RuntimeSelection.Mode.PROROOT,
        RuntimeSelection.downgraded(RuntimeSelection.Mode.AUTO, USABLE, true));
  }

  // ---------------------------------------------------------------- 环境变化

  @Test
  public void environmentChangeResetsOnlyFailureDowngrades() {
    // 由失败降级产生的偏好：环境变了就复位成自动，按新结论重选。
    assertTrue(
        RuntimeSelection.resetForEnvironmentChange(RuntimeSelection.Mode.PROROOT, true));
    assertTrue(RuntimeSelection.resetForEnvironmentChange(RuntimeSelection.Mode.PROOT, true));
    // 用户自己手选的档：环境变化不动它（手动强制优先）。
    assertFalse(
        RuntimeSelection.resetForEnvironmentChange(RuntimeSelection.Mode.PROROOT, false));
    assertFalse(RuntimeSelection.resetForEnvironmentChange(RuntimeSelection.Mode.PROOT, false));
    // 本来就在自动：没有可复位的。
    assertFalse(RuntimeSelection.resetForEnvironmentChange(RuntimeSelection.Mode.AUTO, true));
    assertFalse(RuntimeSelection.resetForEnvironmentChange(null, true));
  }

  // ---------------------------------------------------------------- 通用

  @Test
  public void usableMatchesLadderAndRejectsUnknownTiers() {
    assertTrue(RuntimeSelection.usable(RuntimeSelection.CHROOT, USABLE, true));
    assertFalse(RuntimeSelection.usable(RuntimeSelection.CHROOT, UNUSABLE, true));
    assertTrue(RuntimeSelection.usable(RuntimeSelection.PROOT, UNUSABLE, false));
    assertFalse(RuntimeSelection.usable(null, USABLE, true));
    assertFalse(RuntimeSelection.usable("docker", USABLE, true));
    assertTrue(RuntimeSelection.known(RuntimeSelection.CHROOT));
    assertTrue(RuntimeSelection.known(RuntimeSelection.PROROOT));
    assertTrue(RuntimeSelection.known(RuntimeSelection.PROOT));
    assertFalse(RuntimeSelection.known("auto"));
  }

  @Test
  public void decisionLadderIsImmutable() {
    RuntimeSelection.Decision decision =
        RuntimeSelection.choose(RuntimeSelection.Mode.AUTO, USABLE, true);
    try {
      decision.ladder().add("docker");
      fail();
    } catch (UnsupportedOperationException expected) {
      // 阶梯是共享的不可变值：调用方不能就地改它。
    }
  }
}
