package com.deepseekharness.app.runtime;

import android.content.Context;
import com.deepseekharness.app.backup.AndroidBackupFileSystem;
import com.deepseekharness.app.backup.BackupArchive;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * chroot 引导脚本的落地与复核。
 *
 * <p><b>为什么不放 rootfs 里</b>：这些脚本以 root 执行、又要在降权前被读，属于「APK 侧的
 * 可执行配置」，不能混进用户的 rootfs（会被备份带走、会被受管更新覆盖、还让「rootfs 字节
 * 不该被我们改」这条边界失效）。所以按 {@link RuntimeLauncherAssets} 的同一套做法，
 * 落到应用私有目录下按内容摘要编号的只读槽位。
 *
 * <p><b>为什么不 chmod +x</b>：Android 10+ 的应用私有目录是 noexec 挂载点（W^X），
 * 脚本不可能直接执行。调用方统一用 {@code su -c "sh <path>"} 拉起 —— 读脚本不受 W^X 限制。
 * 这里仍然写 0644，是为了让「它不可执行」这件事在文件权限上也一眼可见。
 *
 * <p><b>为什么内容变一次就换一个目录</b>：否则升级 APK 后 su 可能读到上一次的旧脚本，
 * 出现「装了新版，行为还是旧的」这种最难查的错。摘要不同即新槽位；{@link #verify}
 * 在每次装配前复核字节。
 */
final class ChrootHostScripts {
  /** 必须与 {@code util/WebProcSel.CHROOT_SCRIPTS} 一致 —— 那边用来认启动链。 */
  static final List<String> NAMES = List.of("host-launch.sh", "host-ctl.sh");

  private static final int MAX_BYTES = 256 * 1024;
  private static final Object LOCK = new Object();

  private ChrootHostScripts() {}

  /** 已就位的脚本目录；同时返回用于诊断的摘要。 */
  record Installed(File directory, String sha256) {
    File script(String name) {
      return new File(directory, name);
    }
  }

  static Installed prepare(Context context) throws IOException {
    synchronized (LOCK) {
      var fs = new AndroidBackupFileSystem();
      String data = context.getApplicationInfo().dataDir;
      if (data == null) throw new IOException("CHROOT_SCRIPT_CONTEXT");
      var host =
          com.deepseekharness.app.util.ColdInstallPackages.bindPrivateFiles(
              fs, new File(data), context.getFilesDir());
      File parent = fs.child(host.files, "chroot-scripts");
      String parentType = fs.stat(parent).type;
      if (parentType.equals("MISSING")) fs.directory(parent);
      else if (!parentType.equals("DIRECTORY")) throw new IOException("CHROOT_SCRIPT_ROOT");

      Map<String, byte[]> bytes = read(context);
      var digest = BackupArchive.sha();
      for (var entry : bytes.entrySet()) {
        digest.update(entry.getKey().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        digest.update(entry.getValue());
      }
      String id = BackupArchive.hex(digest.digest());
      File target = fs.child(parent, id);
      if (current(fs, target, bytes)) {
        host.verify(fs);
        return new Installed(target, id);
      }
      if (!fs.stat(target).type.equals("MISSING"))
        target = fs.child(parent, id + "-" + UUID.randomUUID());
      fs.directory(target);
      for (var entry : bytes.entrySet()) fs.atomic(target, entry.getKey(), entry.getValue());
      host.verify(fs);
      if (!current(fs, target, bytes)) throw new IOException("CHROOT_SCRIPT_VERIFICATION");
      return new Installed(target, id);
    }
  }

  /** 每次装配启动命令前复核：脚本被改过就拒绝启动，而不是带着未知脚本去 su。 */
  static void verify(Context context, Installed installed) throws IOException {
    if (installed == null) throw new IOException("CHROOT_SCRIPTS_PREPARED");
    var fs = new AndroidBackupFileSystem();
    if (!current(fs, installed.directory(), read(context)))
      throw new IOException("CHROOT_SCRIPT_CHANGED");
  }

  private static Map<String, byte[]> read(Context context) throws IOException {
    Map<String, byte[]> bytes = new LinkedHashMap<>();
    for (String name : NAMES) {
      // 只认白名单名字，且不允许路径成分 —— 资源名来自常量，不给外部拼接的机会。
      if (name.contains("/") || name.contains("..")) throw new IOException("CHROOT_SCRIPT_NAME");
      try (InputStream input = context.getAssets().open("chroot/" + name);
          ByteArrayOutputStream output = new ByteArrayOutputStream()) {
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
          if (output.size() + count > MAX_BYTES) throw new IOException("CHROOT_SCRIPT_LIMIT");
          output.write(buffer, 0, count);
        }
        if (output.size() == 0) throw new IOException("CHROOT_SCRIPT_EMPTY:" + name);
        bytes.put(name, output.toByteArray());
      }
    }
    return bytes;
  }

  private static boolean current(
      com.deepseekharness.app.backup.BackupFileSystem fs, File root, Map<String, byte[]> expected)
      throws IOException {
    if (!fs.stat(root).type.equals("DIRECTORY")) return false;
    if (!new HashSet<>(fs.list(root)).equals(expected.keySet())) return false;
    for (var entry : expected.entrySet()) {
      File file = fs.child(root, entry.getKey());
      if (!fs.stat(file).type.equals("FILE")) return false;
      if (!Arrays.equals(fs.small(file, MAX_BYTES), entry.getValue())) return false;
    }
    return true;
  }
}
