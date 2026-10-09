package com.deepseekharness.app.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import com.deepseekharness.app.util.Constants;
import java.util.Map;
import org.junit.Test;

public class ConfigStoreRuntimeSettingsTest {
  @Test
  public void missingSettingsUseTheSingleConfigStoreDefaults() {
    var snapshot = ConfigStore.runtimeSettingsFrom(Map.of());
    assertEquals("auto", snapshot.dnsMode);
    assertFalse(snapshot.proroot);
    assertTrue(snapshot.staticLoader);
    assertFalse(snapshot.disableProotSeccomp);
    // 没存过任何运行时偏好 → 自动模式（chroot 由探测结论决定，不由默认值决定）。
    assertEquals(
        com.deepseekharness.app.util.RuntimeSelection.Mode.AUTO, snapshot.mode());
  }

  @Test
  public void anUnselectedColdInstallMayTryFastModeWithoutChangingTheRuntimeDefault() {
    assertTrue(ConfigStore.preferFastColdModeFrom(Map.of()));
    var values = Map.of("dns_mode", "ipv4", "ui_language", "en");
    assertTrue(ConfigStore.preferFastColdModeFrom(values));
    assertFalse(ConfigStore.runtimeSettingsFrom(values).proroot);
  }

  @Test
  public void explicitProotAndHistoricalSelectionRecordsPreventAutomaticFastMode() {
    // "proroot" / "chroot" 是明确表达过的意图，冷安装不得擅自改成快速方式。
    for (Object value : java.util.List.of("proroot", "chroot"))
      assertFalse(
          ConfigStore.preferFastColdModeFrom(Map.of(Constants.KEY_CONTAINER_RUNTIME, value)));
    // 新增 chroot 档位后 proroot 不再是唯一的快档，旧默认值 "proot" 与新的 "auto" 同义，
    // 都表示「用户没要求更快的档」——允许冷安装试用快速候选（语义变化，见 CHANGELOG）。
    for (Object value : java.util.List.of("proot", "auto"))
      assertTrue(
          String.valueOf(value),
          ConfigStore.preferFastColdModeFrom(Map.of(Constants.KEY_CONTAINER_RUNTIME, value)));
    // 类型损坏的历史值（布尔/数字混进字符串键）与无法识别的值按保守处理：
    // 不擅自换掉用户的运行方式（此处判据只看档位，不看 PreferenceValue 的兜底）。
    for (Object value : java.util.List.of(false, true, 1, "docker"))
      assertFalse(
          String.valueOf(value),
          ConfigStore.preferFastColdModeFrom(Map.of(Constants.KEY_CONTAINER_RUNTIME, value)));
    for (String key :
        java.util.List.of("cold_runtime_root", "cold_runtime_packages", "cold_runtime_mode"))
      assertFalse(ConfigStore.preferFastColdModeFrom(Map.of(key, "")));
  }

  @Test
  public void runtimeChoiceSurvivesTheSettingsSnapshotForAllThreeTiers() {
    for (var mode : com.deepseekharness.app.util.RuntimeSelection.Mode.values()) {
      var snapshot =
          ConfigStore.runtimeSettingsFrom(
              Map.of(Constants.KEY_CONTAINER_RUNTIME, mode.stored()));
      assertEquals(mode, snapshot.mode());
      // 历史布尔字段只反映「是不是 proroot」，不因为新增档位而改变语义。
      assertEquals(mode == com.deepseekharness.app.util.RuntimeSelection.Mode.PROROOT,
          snapshot.proroot);
    }
    // 老用户存的是 proot / proroot，升级后意图必须原样保留。
    assertEquals(
        com.deepseekharness.app.util.RuntimeSelection.Mode.PROOT,
        ConfigStore.runtimeSettingsFrom(
                Map.of(Constants.KEY_CONTAINER_RUNTIME, "proot"))
            .mode());
    // 无法识别的值（配置被改坏、旧版实验值）一律回落自动，不能卡住启动。
    assertEquals(
        com.deepseekharness.app.util.RuntimeSelection.Mode.AUTO,
        ConfigStore.runtimeSettingsFrom(
                Map.of(Constants.KEY_CONTAINER_RUNTIME, "docker"))
            .mode());
  }

  @Test
  public void oneMapImageSupportsOldScalarTypesAndNormalizesDns() {
    var snapshot =
        ConfigStore.runtimeSettingsFrom(
            Map.of(
                Constants.KEY_CONTAINER_RUNTIME,
                "proroot",
                Constants.KEY_WORKDIR,
                "/my-project",
                "proroot_static_loader",
                "false",
                "proot_disable_seccomp",
                1,
                "dns_mode",
                "ipv4"));
    assertEquals("ipv4", snapshot.dnsMode);
    assertTrue(snapshot.proroot);
    assertFalse(snapshot.staticLoader);
    assertTrue(snapshot.disableProotSeccomp);
  }

  @Test
  public void historicalEmptyWorkdirDoesNotBlockUnrelatedRuntimeSettings() {
    var history =
        Map.of(
            Constants.KEY_WORKDIR,
            "",
            "dns_mode",
            "ipv4",
            Constants.KEY_CONTAINER_RUNTIME,
            "proroot");
    var snapshot = ConfigStore.runtimeSettingsFrom(history);
    assertEquals("", history.get(Constants.KEY_WORKDIR));
    assertEquals("ipv4", snapshot.dnsMode);
    assertTrue(snapshot.proroot);
    assertTrue(snapshot.staticLoader);
    assertFalse(snapshot.disableProotSeccomp);
  }
}
