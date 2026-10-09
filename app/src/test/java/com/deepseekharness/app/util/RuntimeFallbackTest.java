package com.deepseekharness.app.util;

import java.util.List;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 归因的断言。这一组测试真正防的是「应用层错误被算成运行时错误」——
 * 那会让用户环境无缘无故降级，而且真正的病根永远查不出来。
 */
public final class RuntimeFallbackTest {

  // ---------------------------------------------------------------- 运行时归因

  @Test
  public void mountAndNamespaceFailuresAreRuntimeAttributed() {
    for (String output :
        List.of(
            "mount: '/data/data/com.dsh.client/files/linux/ubuntu/proc' -> 'proc': Permission denied",
            "mount: mounting proc on /proc failed: Permission denied",
            "unshare: unshare failed: Operation not permitted",
            "chroot: failed to run command '/bin/bash': Permission denied",
            "nsenter: cannot open /proc/1234/ns/mnt: No such file or directory",
            "setpriv: failed to execute /bin/bash: Permission denied",
            "avc:  denied  { mounton } for pid=1234",
            "SELinux: mount operation denied"))
      assertEquals(output, RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute(output, 1));
  }

  @Test
  public void suDenialIsRuntimeAttributed() {
    for (String output :
        List.of(
            "su: access denied",
            "su: permission denied",
            "Access denied",
            "root access denied",
            "no root available"))
      assertEquals(output, RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute(output, 1));
  }

  @Test
  public void loaderAndKernelFailuresAreRuntimeAttributed() {
    for (String output :
        List.of(
            "/bin/bash: cannot execute binary file: Exec format error",
            "/bin/bash: error while loading shared libraries: libtalloc.so.2: cannot open shared object file",
            "error: libproroot-runtime.so: missing",
            "proot error: ptrace not permitted",
            "Segmentation fault",
            "Killed"))
      assertEquals(output, RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute(output, 1));
  }

  @Test
  public void terminationSignalsAreRuntimeAttributedEvenWithoutOutput() {
    assertEquals(RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute("", 139));
    assertEquals(RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute(null, 134));
    assertEquals(RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute("", 135));
    assertEquals(RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute("", 132));
    assertTrue(RuntimeFallback.terminatedBySignal(139));
    assertFalse(RuntimeFallback.terminatedBySignal(null));
    assertFalse(RuntimeFallback.terminatedBySignal(1));
  }

  @Test
  public void hostRuntimeErrorCodesAreRuntimeAttributed() {
    for (String output :
        List.of(
            "PROOT_EXECUTABLE_MISSING",
            "PROROOT_TMP_DIR unavailable",
            "BOUNDED_PROROOT_SESSION_UNAVAILABLE",
            "NATIVE_LIBRARY_PREPARATION_FAILED"))
      assertEquals(output, RuntimeFallback.Attribution.RUNTIME, RuntimeFallback.attribute(output, 1));
  }

  // ---------------------------------------------------------------- 应用层归因

  @Test
  public void portAndConfigErrorsAreApplicationAttributed() {
    for (String output :
        List.of(
            "Error: listen EADDRINUSE: address already in use 127.0.0.1:3080",
            "port 3080 is in use",
            "invalid API key",
            "401 Unauthorized",
            "configuration invalid: missing model",
            "failed to parse settings.yaml: malformed at line 3"))
      assertEquals(
          output, RuntimeFallback.Attribution.APPLICATION, RuntimeFallback.attribute(output, 1));
  }

  @Test
  public void pluginAndNodeErrorsAreApplicationAttributed() {
    for (String output :
        List.of(
            "plugin dsh-task-notifier error: cannot resolve dependency",
            "plugin failed to load",
            "TypeError: Cannot read properties of undefined",
            "ReferenceError: foo is not defined",
            "UnhandledPromiseRejection: bad state"))
      assertEquals(
          output, RuntimeFallback.Attribution.APPLICATION, RuntimeFallback.attribute(output, 1));
  }

  @Test
  public void applicationEvidenceWinsWhenBothKindsAppear() {
    // 插件崩了之后 shell 又打了一句 "not found"：少降一级的代价是慢，多降一级的代价是把
    // 环境搞坏。所以应用层签名优先。
    String mixed =
        "plugin manager failed: TypeError: x is not defined\n/bin/sh: dsh: not found";
    assertEquals(RuntimeFallback.Attribution.APPLICATION, RuntimeFallback.attribute(mixed, 127));
    assertFalse(RuntimeFallback.mayDowngrade(mixed, 127));
  }

  // ---------------------------------------------------------------- 未确认

  @Test
  public void unknownEvidenceNeverDowngrades() {
    assertFalse(RuntimeFallback.mayDowngrade("", null));
    assertFalse(RuntimeFallback.mayDowngrade(null, null));
    assertFalse(RuntimeFallback.mayDowngrade("干净退出，没有输出", 0));
    assertEquals(RuntimeFallback.Attribution.UNKNOWN, RuntimeFallback.attribute("干净退出", 0));
    // 退出码 1 本身没有区分度，不能单独作为降级依据。
    assertEquals(RuntimeFallback.Attribution.UNKNOWN, RuntimeFallback.attribute("some output", 1));
    assertFalse(RuntimeFallback.mayDowngrade("some output", 1));
  }

  @Test
  public void onlyRuntimeAttributionMayDowngrade() {
    assertTrue(RuntimeFallback.mayDowngrade("mount: mounting proc failed", 1));
    assertTrue(RuntimeFallback.mayDowngrade("", 139));
    assertFalse(RuntimeFallback.mayDowngrade("EADDRINUSE", 1));
    assertFalse(RuntimeFallback.mayDowngrade("", 0));
  }

  // ---------------------------------------------------------------- 辅助

  @Test
  public void evidenceIsBoundedAndStable() {
    assertEquals("", RuntimeFallback.boundedEvidence(null, 10));
    assertEquals("abc", RuntimeFallback.boundedEvidence("  abc  ", 10));
    String long_ = "x".repeat(100);
    String bounded = RuntimeFallback.boundedEvidence(long_, 10);
    assertEquals(10, bounded.length());
    assertTrue(bounded.endsWith("..."));
    assertEquals(10, RuntimeFallback.boundedEvidence(long_, 10).length());
  }

  @Test
  public void codesAndDescriptionsAreStableIds() {
    assertEquals("runtime", RuntimeFallback.code(RuntimeFallback.Attribution.RUNTIME));
    assertEquals("application", RuntimeFallback.code(RuntimeFallback.Attribution.APPLICATION));
    assertEquals("unknown", RuntimeFallback.code(RuntimeFallback.Attribution.UNKNOWN));
    for (RuntimeFallback.Attribution attribution : RuntimeFallback.Attribution.values())
      assertFalse(RuntimeFallback.describe(attribution).isEmpty());
    // 「不降级」这句提示必须出现在应用层与未确认两种归因里，界面才说得清为什么没降。
    assertTrue(RuntimeFallback.describe(RuntimeFallback.Attribution.APPLICATION).contains("不降级"));
    assertTrue(RuntimeFallback.describe(RuntimeFallback.Attribution.UNKNOWN).contains("不降级"));
  }
}
