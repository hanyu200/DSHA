package com.deepseekharness.app.runtime;

import android.content.Context;
import com.deepseekharness.app.util.ChrootProbe;
import com.deepseekharness.app.util.SensitiveData;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 探测结论的落地与读取。
 *
 * <p><b>为什么探测是「先落盘、后读盘」而不是「启动时同步跑一遍」</b>：
 * 探测要经 {@code su} 跑一条会 {@code unshare}/{@code mount} 的脚本，是秒级且可能弹授权的操作。
 * 把它放进冷启动路径，等于每次开 App 都赌一次 su 授权与 mount 权限 —— 而计划 §2.1 的硬要求
 * 恰恰是「无 root 用户体验必须与上游完全一致（零回归）」。所以拆成两件事：
 * <ul>
 *   <li><b>写</b>：只在两个时机发生 —— 用户点「运行环境探测」，或冷启动发现结论缺失/过期时
 *       提示用户去跑一次。写的时候直接复用阶段 0.5 那份脚本（同一个 {@code probe} 子命令），
 *       因此「设置页跑出来的结论」与「手机上手工跑的结论」是同一份东西。</li>
 *   <li><b>读</b>：冷启动只读文件、解析、给选择用；文件不存在/读不动/格式不对一律当
 *       {@code unknown}（{@link ChrootProbe.Result#unknown}），于是自动落到 proroot/proot ——
 *       fail-closed，不会因为「探测没跑」而把用户卡在启动失败上。</li>
 * </ul>
 *
 * <p><b>路径为什么是 filesDir</b>：脚本以 root 跑、App 以自己 UID 读，两边都能进出的地方就是
 * 应用私有目录。{@code /data/local/tmp} 在部分机型上 app 域读不到（SELinux），所以那不是默认值。
 * 脚本侧可用 {@code DSHA_CHROOT_OUT} 覆盖，这里通过环境变量把路径传给它，保证两边指的是同一处。
 */
final class ChrootProbeStore {
  /** 目录名与 {@code docs/chroot-stage0-smoke.sh} 的默认值必须一致。 */
  static final String DIRECTORY = "chroot-probe";

  static final String REPORT_NAME = "report.txt";
  static final String RESULT_NAME = "probe-result.txt";

  /** 结论保鲜期与上限的权威定义在 {@code ChrootProbe}（纯逻辑，有单测）。 */
  static final long MAX_AGE_MILLIS = ChrootProbe.MAX_AGE_MILLIS;

  private ChrootProbeStore() {}

  static File directory(Context context) {
    return new File(context.getFilesDir(), DIRECTORY);
  }

  static File reportFile(Context context) {
    return new File(directory(context), REPORT_NAME);
  }

  private static File resultFile(Context context) {
    return new File(directory(context), RESULT_NAME);
  }

  /**
   * 读探测结论。任何异常都收敛成 {@code unknown} —— 调用方的分支只需处理「可用/不可用」，
   * 不需要到处 try/catch；失败原因进 detail，诊断里看得到。
   */
  static ChrootProbe.Result read(Context context, long nowMillis) {
    try {
      File report = reportFile(context);
      if (!report.isFile()) return ChrootProbe.Result.unknown("NO_PROBE_REPORT", nowMillis);
      if (report.length() > ChrootProbe.MAX_REPORT_BYTES)
        return ChrootProbe.Result.unknown("REPORT_TOO_LARGE", nowMillis);
      String text =
          new String(
              com.deepseekharness.app.util.Compat.readAllBytes(report), StandardCharsets.UTF_8);
      if (text.isBlank()) return ChrootProbe.Result.unknown("EMPTY_REPORT", nowMillis);
      return ChrootProbe.parse(text, report.lastModified());
    } catch (IOException | RuntimeException error) {
      return ChrootProbe.Result.unknown(
          "REPORT_UNREADABLE:" + SensitiveData.redact(error.getClass().getSimpleName()), nowMillis);
    }
  }

  /** 结论是不是需要重跑（从来没跑过 / 太旧 / 时间戳不可信）。冷启动据此决定要不要提示用户。 */
  static boolean shouldProbe(Context context, long nowMillis) {
    return ChrootProbe.shouldReprobe(read(context, nowMillis), nowMillis);
  }

  /**
   * 把结论另存一份人类可读的结构化报告，供「导出报告」与诊断附件使用。
   *
   * <p>写失败<b>不</b>影响选择 —— 选择读的是 {@code report.txt} 本身。这里存的是加工结果，
   * 属于诊断便利，不该成为启动链的失败点。
   */
  static void saveResult(Context context, ChrootProbe.Result result) {
    try {
      File directory = directory(context);
      if (!directory.isDirectory() && !directory.mkdirs()) return;
      byte[] bytes =
          (ChrootProbe.report(result) + "\n" + ChrootProbe.toJson(result))
              .getBytes(StandardCharsets.UTF_8);
      com.deepseekharness.app.util.Compat.write(resultFile(context), bytes);
    } catch (IOException | RuntimeException ignored) {
      // 诊断便利，失败即放弃；选择不受影响。
    }
  }

  /** 探测脚本要用的报告目录（经环境变量传给脚本）。 */
  static String reportDirectoryPath(Context context) {
    return directory(context).getAbsolutePath();
  }
}
