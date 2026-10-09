package com.deepseekharness.app.runtime;

import android.content.Context;
import com.deepseekharness.app.util.ChrootProbe;
import com.deepseekharness.app.util.SensitiveData;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 运行环境探测的<b>执行入口</b>：把阶段 0.5 那份脚本经 {@code su} 跑一遍，再把结论读回来。
 *
 * <p><b>为什么直接复用真机冒烟脚本</b>：计划的意图是「用户手工在手机上跑的结论」与「设置页
 * 点出来的结论」必须是同一份东西 —— 否则两边的判据会各自漂移，出了分歧也没法判断以谁为准。
 * 所以这里不重写探测逻辑，只做三件事：把脚本放到 root 读得到的地方、调 {@code su} 执行
 * {@code probe} 子命令、读 {@link ChrootProbeStore} 的报告。
 *
 * <p><b>为什么是同步调用</b>：探测会做 {@code unshare}/{@code mount}/{@code chroot}，是秒级
 * 操作，而且 {@code su} 可能弹授权框。调用方必须在<b>后台线程</b>调用它，并在等待期间给用户
 * 明确提示 —— 不能放在冷启动路径上（那会让无 root 用户的每次开 App 都赌一次 su 授权）。
 *
 * <p><b>失败了也不抛</b>：返回的永远是 {@link ChrootProbe.Result}，读不到就是 {@code unknown}，
 * 于是自动落到 proroot/proot。探测失败不该让设置页崩，也不该影响选择链路的 fail-closed 性质。
 */
final class ChrootProbeRunner {

  /** 探测可能弹 su 授权，给足时间但仍要有界，避免永久占着后台线程。 */
  static final long TIMEOUT_MILLIS = 120_000;

  /** 输出上限：探测脚本会打印挂载清单与进程表，读太多没意义。 */
  private static final int MAX_OUTPUT = 64 * 1024;

  private ChrootProbeRunner() {}

  /**
   * 跑一次探测并返回结论。
   *
   * @param onStage 进度回调（可为 null）；只回传稳定的阶段 ID，不拼界面文案
   */
  static ChrootProbe.Result run(Context context, java.util.function.Consumer<String> onStage) {
    long now = System.currentTimeMillis();
    try {
      File scripts = installScript(context);
      if (scripts == null) return ChrootProbe.Result.unknown("PROBE_SCRIPT_MISSING", now);
      if (onStage != null) onStage.accept("running");
      Outcome outcome = execute(context, scripts);
      // 脚本把结论打在 stdout；落成与真机冒烟脚本同名的 report.txt，
      // 于是「设置页跑的」与「手机手工跑的」是同一份文件、同一套判据。
      if (outcome.output() != null && !outcome.output().isBlank()) {
        writeReport(context, outcome.output());
      }
      ChrootProbe.Result result = ChrootProbeStore.read(context, System.currentTimeMillis());
      ChrootProbeStore.saveResult(context, result);
      if (onStage != null) onStage.accept(result.readable() ? "done" : "failed");
      if (outcome.exitCode() != null && outcome.exitCode() != 0 && !result.readable())
        return ChrootProbe.Result.unknown("PROBE_EXIT:" + outcome.exitCode(), now);
      return result;
    } catch (IOException | RuntimeException failure) {
      if (onStage != null) onStage.accept("failed");
      return ChrootProbe.Result.unknown(
          "PROBE_FAILED:" + SensitiveData.redact(failure.getClass().getSimpleName()), now);
    }
  }

  private record Outcome(Integer exitCode, String output) {}

  /**
   * 把探测输出写成报告文件。写失败<b>不</b>影响本次结论（输出已在内存里），
   * 只影响「下次冷启动能不能读到」——所以这里记为尽力而为。
   */
  private static void writeReport(Context context, String output) {
    try {
      File directory = new File(context.getFilesDir(), ChrootProbeStore.DIRECTORY);
      if (!directory.isDirectory() && !directory.mkdirs()) return;
      com.deepseekharness.app.util.Compat.write(
          new File(directory, ChrootProbeStore.REPORT_NAME),
          output.getBytes(StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException ignored) {
      // 尽力而为：本次结论仍会返回给调用方。
    }
  }

  /**
   * 把探测脚本从 APK 取出来放到 root 读得到的地方。
   *
   * <p>放应用私有目录而不是 {@code /data/local/tmp}：后者在部分机型上 app 域读不到，而
   * 「写进去、读回来」两边都得通。这里写进去的是 root（su 域），读回来的是 app 自己。
   */
  private static File installScript(Context context) throws IOException {
    File directory = new File(context.getFilesDir(), ChrootProbeStore.DIRECTORY);
    if (!directory.isDirectory() && !directory.mkdirs()) return null;
    File script = new File(directory, "dsha-chroot-probe.sh");
    byte[] bytes = readAsset(context, "chroot/host-probe.sh");
    if (bytes == null) return null;
    // 每次都覆盖：脚本随 APK 版本变化，留着旧的会出现「装了新版、探测判据还是旧的」。
    com.deepseekharness.app.util.Compat.write(script, bytes);
    return script;
  }

  private static byte[] readAsset(Context context, String name) {
    try (InputStream input = context.getAssets().open(name)) {
      byte[] buffer = new byte[8192];
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      int count;
      while ((count = input.read(buffer)) != -1) {
        if (output.size() + count > 512 * 1024) return null;
        output.write(buffer, 0, count);
      }
      return output.size() == 0 ? null : output.toByteArray();
    } catch (IOException | RuntimeException missing) {
      return null;
    }
  }

  /** 调 {@code su -c "sh <脚本> probe"}；脚本路径作为独立 argv，不经引号拼接。 */
  private static Outcome execute(Context context, File script) throws IOException {
    ProcessBuilder builder =
        new ProcessBuilder("su", "-c", "sh \"$0\" probe", script.getAbsolutePath());
    builder.redirectErrorStream(true);
    // 报告目录与包名必须由 app 指定并与 ChrootProbeStore 一致：脚本里的默认值只是给人手工跑用的。
    builder
        .environment()
        .put("DSHA_CHROOT_OUT", ChrootProbeStore.reportDirectoryPath(context));
    builder.environment().put("DSHA_CHROOT_PKG", context.getPackageName());
    Process process = builder.start();
    try {
      String output = drain(process.getInputStream());
      if (!process.waitFor(TIMEOUT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) {
        // 超时只做「请求结束」，不强杀：su 可能在等授权框，杀掉会让下一次授权状态不明。
        com.deepseekharness.app.util.Compat.destroy(process);
        return new Outcome(null, output);
      }
      return new Outcome(process.exitValue(), output);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      com.deepseekharness.app.util.Compat.destroy(process);
      return new Outcome(null, "");
    }
  }

  /** 读走全部输出（有界）：探测脚本会打印挂载清单与进程表，读不完会把它堵死。 */
  private static String drain(InputStream input) {
    StringBuilder text = new StringBuilder();
    try (InputStream stream = input) {
      byte[] buffer = new byte[4096];
      int total = 0;
      while (total < MAX_OUTPUT) {
        int count = stream.read(buffer, 0, Math.min(buffer.length, MAX_OUTPUT - total));
        if (count <= 0) break;
        total += count;
        text.append(new String(buffer, 0, count, StandardCharsets.UTF_8));
      }
    } catch (IOException ignored) {
      // 读中断时保留已读到的部分：报告里有几行就解析几行，缺项会让 chroot 判为不可用（fail-closed）。
    }
    return text.toString();
  }

  /** 诊断用：探测脚本是否已落地（不看内容，只看存在性）。 */
  static boolean scriptPresent(Context context) {
    return new File(new File(context.getFilesDir(), ChrootProbeStore.DIRECTORY),
            "dsha-chroot-probe.sh")
        .isFile();
  }

  /** 诊断用：一行结论摘要。 */
  static String summarize(ChrootProbe.Result result) {
    if (result == null || !result.readable()) return "unreadable";
    return (ChrootProbe.chrootUsable(result) ? "usable" : "blocked:" + result.blocking())
        + " @" + result.atMillis();
  }

  /** 供测试与诊断复用：把结论转成 UTF-8 文本。 */
  static String asText(ChrootProbe.Result result) {
    return new String(ChrootProbe.report(result).getBytes(StandardCharsets.UTF_8),
        StandardCharsets.UTF_8);
  }
}
