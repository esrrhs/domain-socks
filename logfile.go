package main

import (
	"fmt"
	"os"
	"sync"
)

// rotatingWriter 是零依赖的按大小日志轮转 writer：当前文件超过 maxSize
// 前滚为 path.1（旧备份依次后移，最老的 path.N 删除），再开新文件继续写。
// 路由器 flash/tmpfs 空间有限，历史日志总量因此被硬限制在
// maxSize*(backups+1) 字节。写入错误一律吞掉（尽力而为，不能因为磁盘
// 满而中断代理进程）；log 包每条记录只做一次 Write，记录不会被拆开。
type rotatingWriter struct {
	path    string
	maxSize int64
	backups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// newRotatingWriter 打开（不存在则创建）日志文件并定位到尾部续接：
// 进程被 procd 重启后能接着原有文件写，保留崩溃前的历史。
func newRotatingWriter(path string, maxSize int64, backups int) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path, maxSize: maxSize, backups: backups}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	w.f = f
	if fi, err := f.Stat(); err == nil {
		w.size = fi.Size()
	}
	return w, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil
	}
	// size==0 时不轮转：保证一条超大记录（大于 maxSize）也完整落盘，
	// 而不是反复改名打开空文件。
	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		if err := w.rotateLocked(); err != nil {
			// 轮转失败就继续往旧文件写，日志不丢给进程
			_ = err
		}
	}
	n, _ := w.f.Write(p)
	w.size += int64(n)
	// 永远返回成功：log 的输出端故障不应影响数据面
	return len(p), nil
}

// rotateLocked 执行 .N 删除、(.i -> .i+1) 整体后移与 path -> path.1，
// 然后打开新的空文件。备份目标先删后改名，兼容 Windows
// （os.Rename 在 Windows 上不能覆盖已存在文件）。
func (w *rotatingWriter) rotateLocked() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	if w.backups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.backups))
		for i := w.backups - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i),
				fmt.Sprintf("%s.%d", w.path, i+1))
		}
		_ = os.Rename(w.path, w.path+".1")
	} else {
		_ = os.Remove(w.path)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.f = nil
		return err
	}
	w.f = f
	w.size = 0
	return nil
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
