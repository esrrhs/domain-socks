package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFile 小工具：不存在返回 ("", false)
func readFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// TestRotatingWriterRotation 写远超单文件容量的记录，验证：
// 当前文件与 .1/.2 备份齐备、.3 不存在、每条记录恰好出现一次、
// 单文件不超过 maxSize+单条记录长度、按 .2 -> .1 -> 当前顺序可完整还原。
func TestRotatingWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")
	const maxSize = 64
	const backups = 2
	const recLen = 15 // len("log-record-000\n")
	w, err := newRotatingWriter(path, maxSize, backups)
	if err != nil {
		t.Fatal(err)
	}

	// 12 条 x 15B = 180B：恰好两次轮转（每个文件装 4 条），
	// .2/.1/当前三文件保留全部记录，.3 不产生。
	var want []string
	for i := 0; i < 12; i++ {
		line := fmt.Sprintf("log-record-%03d\n", i)
		want = append(want, line)
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"ds.log", "ds.log.1", "ds.log.2"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Size() == 0 {
			t.Fatalf("%s missing or empty (err=%v)", name, err)
		}
	}
	if _, ok := readFile(t, filepath.Join(dir, "ds.log.3")); ok {
		t.Fatal("ds.log.3 must not exist: backups capped at 2")
	}

	// 每个文件不得超过 maxSize+单条记录（触发轮转后新文件从 0 起）
	for _, name := range []string{"ds.log", "ds.log.1", "ds.log.2"} {
		if fi, _ := os.Stat(filepath.Join(dir, name)); fi.Size() > maxSize+recLen {
			t.Fatalf("%s size=%d exceeds bound %d", name, fi.Size(), maxSize+recLen)
		}
	}

	// 按时间顺序拼接全部文件（.2 最老 -> .1 -> 当前），20 条记录一条不少
	concat, _ := readFile(t, filepath.Join(dir, "ds.log.2"))
	s1, _ := readFile(t, filepath.Join(dir, "ds.log.1"))
	cur, _ := readFile(t, filepath.Join(dir, "ds.log"))
	concat += s1 + cur
	for _, line := range want {
		if c := strings.Count(concat, line); c != 1 {
			t.Fatalf("record %q appears %d times, want exactly 1", strings.TrimSpace(line), c)
		}
	}
}

// TestRotatingWriterResume 验证 procd 重启场景：重新打开同名文件后
// 追加写入并沿用既有大小，轮转时旧生命期的记录进入备份。
func TestRotatingWriterResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")

	w1, err := newRotatingWriter(path, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w1.Write([]byte("first-life\n"))
	_ = w1.Close()

	w2, err := newRotatingWriter(path, 20, 2) // 容量调小，制造跨重启轮转
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w2.Write([]byte("second-life-line\n")) // 追加后超过 20B，first-life -> .1
	_, _ = w2.Write([]byte("third-life-line\n"))  // 再次轮转：.1 -> .2，second -> .1
	_ = w2.Close()

	cur, curOK := readFile(t, path)
	if !curOK {
		t.Fatal("current log missing")
	}
	if !strings.Contains(cur, "third-life-line") {
		t.Fatalf("new record must be in current file:\n%s", cur)
	}
	bak1, ok1 := readFile(t, path+".1")
	if !ok1 || !strings.Contains(bak1, "second-life") {
		t.Fatalf(".1 must hold second-life, got ok=%v:\n%s", ok1, bak1)
	}
	bak2, ok2 := readFile(t, path+".2")
	if !ok2 || !strings.Contains(bak2, "first-life") {
		t.Fatalf(".2 must preserve pre-restart first-life, got ok=%v:\n%s", ok2, bak2)
	}
}

// TestRotatingWriterOversizeRecord 单条超大记录必须完整落盘，
// 不能因为超过 maxSize 被反复轮转丢失。
func TestRotatingWriterOversizeRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")
	w, err := newRotatingWriter(path, 16, 1)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("B", 100) + "\n"
	_, _ = w.Write([]byte(big))
	_ = w.Close()
	got, ok := readFile(t, path)
	if !ok || !strings.Contains(got, big) {
		t.Fatalf("oversize record must land intact, ok=%v len=%d", ok, len(got))
	}
}

// TestRotatingWriterZeroBackups backups=0 时直接截断重开，不留任何备份。
func TestRotatingWriterZeroBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")
	w, err := newRotatingWriter(path, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("aaaa\n"))
	_, _ = w.Write([]byte("bbbb\n")) // 触发轮转：删旧建新
	_ = w.Close()
	got, _ := readFile(t, path)
	if got != "bbbb\n" {
		t.Fatalf("current file=%q want only latest record", got)
	}
	if _, ok := readFile(t, path+".1"); ok {
		t.Fatal("no backup files allowed with backups=0")
	}
}

// TestRotatingWriterReopen 模拟外部 logrotate：旧文件被 rename 后，
// 不 reopen 写入仍落旧 inode；Reopen 后必须写到同路径的新文件，
// 旧文件保留被切走时的内容（postrotate 可压缩归档）。
func TestRotatingWriterReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")
	rotated := path + ".1"

	w, err := newRotatingWriter(path, 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("before-rotation\n"))

	// logrotate 的 rename 动作（不发 copytruncate）
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}

	// reopen 前：写入仍跟随旧 fd（被 rename 的文件）
	_, _ = w.Write([]byte("still-old-inode\n"))
	if _, ok := readFile(t, path); ok {
		t.Fatal("path must not exist before reopen: writer still holds the renamed inode")
	}
	old, _ := readFile(t, rotated)
	if !strings.Contains(old, "still-old-inode") {
		t.Fatalf("renamed file should keep pre-reopen writes:\n%s", old)
	}

	if err := w.Reopen(); err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("after-reopen\n"))
	_ = w.Close()

	cur, ok := readFile(t, path)
	if !ok || !strings.Contains(cur, "after-reopen") {
		t.Fatalf("post-reopen write must land at the path again, ok=%v:\n%s", ok, cur)
	}
	if strings.Contains(cur, "before-rotation") {
		t.Fatalf("new file must not contain pre-rotation bytes:\n%s", cur)
	}
	// 被切走的旧文件内容未被破坏
	old2, _ := readFile(t, rotated)
	if !strings.Contains(old2, "before-rotation") || !strings.Contains(old2, "still-old-inode") {
		t.Fatalf("rotated file contents changed:\n%s", old2)
	}
}

// TestRotatingWriterReopenFailure reopen 目标目录消失：返回错误且后续
// 写入静默丢弃（只剩 stderr），不 panic、不影响调用方。
func TestRotatingWriterReopenFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.log")
	w, err := newRotatingWriter(path, 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := w.Reopen(); err == nil {
		t.Fatal("reopen into a removed dir must fail")
	}
	if n, err := w.Write([]byte("into-the-void\n")); n != len("into-the-void\n") || err != nil {
		t.Fatalf("write after failed reopen must be swallowed, got n=%d err=%v", n, err)
	}
}
