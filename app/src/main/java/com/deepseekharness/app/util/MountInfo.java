package com.deepseekharness.app.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * {@code /proc/<pid>/mountinfo} 的解析（纯逻辑，不碰 Android API —— 断言在 JVM 单元测试里）。
 *
 * <p><b>为什么要单独一个类</b>：chroot 的挂载全部发生的自己的 mount namespace 里，
 * 「到底挂上了没有」「进程退出后清干净没有」只能问内核，而唯一可问的地方就是 mountinfo。
 * 这段解析此前会散在诊断、自检、清理三处各写一遍 —— 那正是本项目反复栽跟头的模式
 * （同一份判断散落多处，改一处漏三处）。收成一份之后可以写断言钉住：
 *
 * <ul>
 *   <li>挂载点里可以有空格（{@code /root/手机存储}），所以<b>不能</b>按空白直接 split；</li>
 *   <li>字段 5 是挂载点，字段 10 才是源设备 —— 顺序错位会把「源」当成「挂载点」；</li>
 *   <li>可选的 {@code tag:value} 段（{@code shared:} / {@code master:}）长度不固定，
 *       它决定文件系统类型在哪个位置，按固定下标取会错。</li>
 * </ul>
 *
 * <p>格式（内核文档 {@code proc(5)}）：
 * <pre>
 * 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
 * (1)(2)(3)  (4)   (5)   (6)      (7)   (8)(9) (10)        (11)
 * </pre>
 */
public final class MountInfo {

  private MountInfo() {}

  /** 一条挂载记录里我们关心的三个字段。 */
  public record Entry(int mountId, String mountPoint, String source, String fileSystem) {

    public Entry {
      mountPoint = mountPoint == null ? "" : mountPoint;
      source = source == null ? "" : source;
      fileSystem = fileSystem == null ? "" : fileSystem;
    }
  }

  /**
   * 解析整份 mountinfo。
   *
   * <p>畸形行<b>跳过而不是抛异常</b>：这是内核给的实时数据，解析期间挂载点可能正在消失，
   * 让一整行坏数据把诊断打断不划算；调用方拿到的是「能解析出来的那些」。
   */
  public static List<Entry> parse(String text) {
    List<Entry> entries = new ArrayList<>();
    if (text == null || text.isEmpty()) return List.copyOf(entries);
    for (String raw : text.split("\n")) {
      Entry entry = parseLine(raw);
      if (entry != null) entries.add(entry);
    }
    return List.copyOf(entries);
  }

  /** 解析单行；不是有效挂载记录时返回 null。 */
  public static Entry parseLine(String line) {
    if (line == null) return null;
    // 只切前 5 个字段（id / parent / major:minor / root / 挂载点），第 6 段留给「其余全部」。
    // 为什么限 6 而不是 7：可选段（shared: / master:）是可选的，没有它时第 7 个字段恰好就是
    // 分隔符 "-"，会被 split 当成一个独立字段吃掉，于是「找 ' - '」永远找不到。
    String[] head = line.trim().split(" ", 6);
    if (head.length < 6) return null;
    Integer mountId = parseInt(head[0]);
    if (mountId == null) return null;
    String mountPoint = head[4];
    if (mountPoint.isEmpty()) return null;
    // 第 6 段 = 挂载选项 [可选 tag:value …] - fsType source 超级块选项。
    // 分隔符统一写成 " - "，所以判据是「找得到 ' - '」而不是「以 '- ' 开头」。
    String remainder = head[5];
    int separator = remainder.indexOf(" - ");
    if (separator < 0) return null;
    String[] tail = remainder.substring(separator + 3).split(" ", 3);
    if (tail.length < 2) return null;
    String mountPointUnescaped = unescape(mountPoint);
    if (mountPointUnescaped.isEmpty()) return null;
    return new Entry(mountId, mountPointUnescaped, unescape(tail[1]), tail[0]);
  }

  /**
   * 挑出挂载点在给定根（含根本身）之下的记录，按挂载点<b>从深到浅</b>排序。
   *
   * <p>从深到浅是有意的：拆挂载必须后挂的先拆，浅的先拆会留下被遮住、之后再也卸不掉的
   * 「隐藏挂载」。
   */
  public static List<Entry> under(List<Entry> entries, String root) {
    if (entries == null || root == null || root.isEmpty()) return List.of();
    String prefix = root.endsWith("/") ? root.substring(0, root.length() - 1) : root;
    List<Entry> selected = new ArrayList<>();
    for (Entry entry : entries) {
      String point = entry.mountPoint();
      if (point.equals(prefix) || point.startsWith(prefix + "/")) selected.add(entry);
    }
    selected.sort(
        (left, right) -> {
          int byDepth = Integer.compare(depth(right.mountPoint()), depth(left.mountPoint()));
          return byDepth != 0 ? byDepth : left.mountPoint().compareTo(right.mountPoint());
        });
    return List.copyOf(selected);
  }

  private static int depth(String path) {
    int count = 0;
    for (int index = 0; index < path.length(); index++) if (path.charAt(index) == '/') count++;
    return count;
  }

  /** 内核把空格、制表、换行、反斜杠转义成八进制，读回时要还原。 */
  public static String unescape(String value) {
    if (value == null || value.indexOf('\\') < 0) return value == null ? "" : value;
    StringBuilder out = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (current != '\\' || index + 3 >= value.length()) {
        out.append(current);
        continue;
      }
      Integer octet = octal(value, index + 1);
      if (octet == null) {
        out.append(current);
        continue;
      }
      out.append((char) (int) octet);
      index += 3;
    }
    return out.toString();
  }

  private static Integer octal(String value, int from) {
    int result = 0;
    for (int index = from; index < from + 3; index++) {
      char digit = value.charAt(index);
      if (digit < '0' || digit > '7') return null;
      result = result * 8 + (digit - '0');
    }
    return result;
  }

  private static Integer parseInt(String value) {
    try {
      return Integer.valueOf(value.trim());
    } catch (NumberFormatException notANumber) {
      return null;
    }
  }

  /** 诊断用：把记录渲染成稳定的一行（不随界面语言变化）。 */
  public static String describe(Entry entry) {
    if (entry == null) return "";
    return String.format(
        Locale.ROOT, "%s <- %s (%s)", entry.mountPoint(), entry.source(), entry.fileSystem());
  }
}
