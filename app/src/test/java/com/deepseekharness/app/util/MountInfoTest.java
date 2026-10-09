package com.deepseekharness.app.util;

import java.util.List;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * mountinfo 解析的断言。
 *
 * <p>重点是三处「写错了也能跑、但结果静默错位」的地方：挂载点/源设备的字段下标、
 * 可选 {@code tag:value} 段导致的不固定长度、以及内核的八进制转义。
 */
public final class MountInfoTest {

  private static final String SAMPLE =
      String.join(
          "\n",
          // (1) 最普通的一条
          "36 35 98:0 /mnt1 /mnt2 rw,noatime - ext3 /dev/root rw,errors=continue",
          // (2) 带 shared: 的 tmpfs（可选段更长）
          "40 36 0:38 / /dev/shm rw,nosuid,nodev shared:12 - tmpfs tmpfs rw,size=65536k",
          // (3) 带 master: 可选段
          "41 36 0:39 / /dev/pts rw,seclabel master:3 - devpts devpts rw,gid=5,mode=620",
          // (4) 没有可选段
          "25 30 0:23 / /proc rw,relatime - proc proc rw",
          // (5) 挂载点转义（文件名里有空格）
          "50 36 0:44 / /root/with\\040space rw - tmpfs tmpfs rw",
          // (6) 畸形：字段不够
          "60 36 0:45 / /truncated rw",
          // (7) 畸形：没有 " - " 分隔符
          "70 36 0:46 / /nodash rw,relatime ext4 /dev/x rw",
          // (8) 空行
          "");

  /**
   * 真实设备形状：注意第 4 个字段是 root（挂载在文件系统内的根，通常为 {@code /}），
   * 第 5 个才是挂载点 —— 少写一个字段就会把「挂载选项」当成挂载点。
   */
  private static final String REAL =
      String.join(
          "\n",
          "128 45 0:120 / /data/user/0/com.dsh.client/files/linux/ubuntu "
              + "rw,seclabel,relatime shared:121 - ext4 /dev/block/dm-56 rw,seclabel",
          "129 128 0:24 / /data/user/0/com.dsh.client/files/linux/ubuntu/proc "
              + "rw,relatime master:1 - proc proc rw",
          "130 128 0:40 / /data/user/0/com.dsh.client/files/linux/ubuntu/dev/pts "
              + "rw,relatime master:2 - devpts devpts rw,gid=5,mode=620,ptmxmode=000");

  /** 少了前 5 个字段的真实格式行（我们只解析完整行，这里用来确认判据不是「以 - 开头」）。 */
  @Test
  public void separatorIsFoundEvenWhenOptionalSegmentsPrecedeIt() {
    // 可选段与分隔符在同一个字段里：判据必须是「找得到 ' - '」，不是「以 '- ' 开头」。
    assertTrue(MountInfo.parseLine("1 2 0:1 / /x rw shared:9 - tmpfs tmpfs rw") != null);
    assertTrue(MountInfo.parseLine("1 2 0:1 / /x rw master:9 - tmpfs tmpfs rw") != null);
    // 没有可选段时，分隔符后面紧跟 fsType —— 这一条是回归点：
    // 按 7 段切会把分隔符自身当成一个字段吃掉，于是永远找不到 " - "。
    MountInfo.Entry plain = MountInfo.parseLine("1 2 0:1 / /x rw - tmpfs tmpfs rw");
    assertTrue(String.valueOf(plain), plain != null);
    assertEquals("/x", plain.mountPoint());
    assertEquals("tmpfs", plain.source());
  }

  @Test
  public void parsesRealDeviceShape() {
    List<MountInfo.Entry> entries = MountInfo.parse(REAL);
    assertEquals(3, entries.size());
    assertEquals(
        "/data/user/0/com.dsh.client/files/linux/ubuntu", entries.get(0).mountPoint());
    assertEquals("/dev/block/dm-56", entries.get(0).source());
    assertEquals("ext4", entries.get(0).fileSystem());
    assertEquals(
        "/data/user/0/com.dsh.client/files/linux/ubuntu/dev/pts", entries.get(2).mountPoint());
    assertEquals("devpts", entries.get(2).source());
    // 从深到浅：先拆 dev/pts，最后才是 rootfs 自己的 self-bind。
    List<MountInfo.Entry> teardown =
        MountInfo.under(entries, "/data/user/0/com.dsh.client/files/linux/ubuntu");
    assertEquals(3, teardown.size());
    assertTrue(teardown.get(0).mountPoint().endsWith("/dev/pts"));
    assertEquals(
        "/data/user/0/com.dsh.client/files/linux/ubuntu",
        teardown.get(teardown.size() - 1).mountPoint());
  }

  @Test
  public void parsesMountPointAndSourceFromTheirRealPositions() {
    List<MountInfo.Entry> entries = MountInfo.parse(SAMPLE);
    // 5 条有效、2 条畸形被跳过（跳过而不是抛异常：内核数据在解析期间也可能变）。
    assertEquals(5, entries.size());
    MountInfo.Entry first = entries.get(0);
    assertEquals(36, first.mountId());
    assertEquals("/mnt2", first.mountPoint());
    assertEquals("/dev/root", first.source());
    assertEquals("ext3", first.fileSystem());
  }

  @Test
  public void optionalTagSegmentsDoNotShiftTheFields() {
    List<MountInfo.Entry> entries = MountInfo.parse(SAMPLE);
    // shared:12 让文件系统类型的位置比第一行更靠后；按固定下标取会错位。
    MountInfo.Entry shared = entries.get(1);
    assertEquals("/dev/shm", shared.mountPoint());
    assertEquals("tmpfs", shared.source());
    assertEquals("tmpfs", shared.fileSystem());
    // master:3 同理。
    MountInfo.Entry master = entries.get(2);
    assertEquals("/dev/pts", master.mountPoint());
    assertEquals("devpts", master.source());
    assertEquals("devpts", master.fileSystem());
    // 没有可选段的也要对。
    MountInfo.Entry plain = entries.get(3);
    assertEquals("/proc", plain.mountPoint());
    assertEquals("proc", plain.source());
    assertEquals("proc", plain.fileSystem());
  }

  @Test
  public void decodesKernelOctalEscapes() {
    // 内核把空格写成 \040；不还原就永远匹配不上真实路径。
    assertEquals("/root/with space", MountInfo.parse(SAMPLE).get(4).mountPoint());
    assertEquals("/a b", MountInfo.unescape("/a\\040b"));
    assertEquals("/a\tb", MountInfo.unescape("/a\\011b"));
    assertEquals("/a\\b", MountInfo.unescape("/a\\134b"));
    // 不是合法八进制时原样保留，不能吃掉字符。
    assertEquals("/a\\9b", MountInfo.unescape("/a\\9b"));
    assertEquals("/a\\04", MountInfo.unescape("/a\\04"));
    assertEquals("", MountInfo.unescape(null));
    assertEquals("/plain", MountInfo.unescape("/plain"));
  }

  @Test
  public void rejectsMalformedLinesAndEmptyInput() {
    assertNull(MountInfo.parseLine(null));
    assertNull(MountInfo.parseLine(""));
    assertNull(MountInfo.parseLine("60 36 0:45 / /truncated rw"));
    // 少了 " - " 分隔符：后半段根本不是「fsType source」。
    assertNull(MountInfo.parseLine("70 36 0:46 / /nodash rw,relatime ext4 /dev/x rw"));
    // 首字段不是数字。
    assertNull(MountInfo.parseLine("x 36 0:45 / /a rw - tmpfs tmpfs rw"));
    assertEquals(List.of(), MountInfo.parse(null));
    assertEquals(List.of(), MountInfo.parse(""));
  }

  @Test
  public void underSelectsTheSubtreeAndSortsDeepestFirst() {
    List<MountInfo.Entry> entries =
        MountInfo.parse(
            String.join(
                "\n",
                "1 0 0:1 / / rw - ext4 /dev/root rw",
                "2 0 0:2 / /data rw - ext4 /dev/block/data rw",
                "3 0 0:3 / /data/user/0/com.dsh.client/files/linux/ubuntu rw - ext4 /dev/x rw",
                "4 0 0:4 / /data/user/0/com.dsh.client/files/linux/ubuntu/proc rw - proc proc rw",
                "5 0 0:5 / /data/user/0/com.dsh.client/files/linux/ubuntu/dev/pts rw - devpts devpts rw",
                "6 0 0:6 / /data/unrelated rw - ext4 /dev/y rw"));
    assertEquals(6, entries.size());
    String root = "/data/user/0/com.dsh.client/files/linux/ubuntu";
    List<MountInfo.Entry> selected = MountInfo.under(entries, root);
    // 子树里共 3 条：rootfs self-bind、proc、dev/pts。同级的 /data 与 /data/unrelated
    // 不能混进来（路径前缀相等 ≠ 子树成员）。
    assertEquals(3, selected.size());
    // 从深到浅：后挂的先拆，否则会留下被遮住、再也卸不掉的隐藏挂载。
    assertEquals(root + "/dev/pts", selected.get(0).mountPoint());
    assertEquals(root + "/proc", selected.get(1).mountPoint());
    // 根自己那条（self-bind）排最后 —— 它就是最后才该拆的那个。
    assertEquals(root, selected.get(selected.size() - 1).mountPoint());
  }

  @Test
  public void underIgnoresPrefixLookalikesAndEmptyRoot() {
    List<MountInfo.Entry> entries =
        MountInfo.parse(
            String.join(
                "\n",
                "1 0 0:1 / /rootfs rw - ext4 /dev/a rw",
                "2 0 0:2 / /rootfs-other rw - ext4 /dev/b rw"));
    // /rootfs-other 不是 /rootfs 的子树：字符串前缀相等但路径边界不同。
    List<MountInfo.Entry> selected = MountInfo.under(entries, "/rootfs");
    assertEquals(1, selected.size());
    assertEquals("/rootfs", selected.get(0).mountPoint());
    assertEquals(List.of(), MountInfo.under(entries, ""));
    assertEquals(List.of(), MountInfo.under(entries, null));
    assertEquals(List.of(), MountInfo.under(null, "/rootfs"));
    // 末尾斜杠不影响判据。
    assertEquals(1, MountInfo.under(entries, "/rootfs/").size());
  }

  @Test
  public void describeIsStableForDiagnostics() {
    MountInfo.Entry entry = MountInfo.parse(SAMPLE).get(0);
    assertEquals("/mnt2 <- /dev/root (ext3)", MountInfo.describe(entry));
    assertEquals("", MountInfo.describe(null));
  }
}
