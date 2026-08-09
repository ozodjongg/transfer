package transfer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const transferBufferSize = 1024 * 1024 // 1 MiB network/control buffer

var transferBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, transferBufferSize)
		return &buf
	},
}

func getTransferBuffer() (*[]byte, func()) {
	p := transferBufferPool.Get().(*[]byte)
	return p, func() { transferBufferPool.Put(p) }
}

type ProgressWriter struct {
	mu         sync.Mutex
	Total      int64
	Done       int64
	BaseOffset int64
	Label      string

	startedAt  time.Time
	lastPrint  time.Time
	lastDone   int64
	emaBytesPS float64
	printed    bool
}

func NewProgressWriter(label string, total, baseOffset int64) *ProgressWriter {
	now := time.Now()
	return &ProgressWriter{
		Total: total, Done: baseOffset, BaseOffset: baseOffset, Label: label,
		startedAt: now, lastPrint: now, lastDone: baseOffset,
	}
}

func (p *ProgressWriter) Write(b []byte) (int, error) {
	p.Add(int64(len(b)))
	return len(b), nil
}

func (p *ProgressWriter) Add(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n <= 0 {
		return
	}
	p.Done += n
	if p.Done > p.Total {
		p.Done = p.Total
	}
	now := time.Now()
	if now.Sub(p.lastPrint) >= 500*time.Millisecond || p.Done >= p.Total {
		p.print(now)
	}
}

func (p *ProgressWriter) print(now time.Time) {
	sampleSeconds := now.Sub(p.lastPrint).Seconds()
	if sampleSeconds > 0 {
		instant := float64(p.Done-p.lastDone) / sampleSeconds
		if p.emaBytesPS == 0 {
			p.emaBytesPS = instant
		} else {
			p.emaBytesPS = p.emaBytesPS*0.72 + instant*0.28
		}
	}

	pct := 100.0
	if p.Total > 0 {
		pct = float64(p.Done) * 100 / float64(p.Total)
	}
	eta := "--:--"
	if p.emaBytesPS > 1 && p.Done < p.Total {
		eta = HumanDuration(time.Duration(float64(p.Total-p.Done)/p.emaBytesPS) * time.Second)
	} else if p.Done >= p.Total {
		eta = "00:00"
	}

	fmt.Printf("\r%-14s %6.2f%% | %s / %s | %s/s | ETA %s",
		p.Label+":", pct, HumanBytes(p.Done), HumanBytes(p.Total), HumanBytes(int64(p.emaBytesPS)), eta)
	p.lastPrint = now
	p.lastDone = p.Done
	p.printed = true
}

func (p *ProgressWriter) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.printed || p.lastDone != p.Done {
		p.print(time.Now())
	}
	if p.printed {
		fmt.Println()
	}
}

func (p *ProgressWriter) Snapshot() (done int64, elapsed time.Duration, avgBytesPerSecond float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	elapsed = time.Since(p.startedAt)
	done = p.Done
	transferred := p.Done - p.BaseOffset
	if elapsed > 0 {
		avgBytesPerSecond = float64(transferred) / elapsed.Seconds()
	}
	return
}

func HumanBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit && exp < 5; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int64(d.Round(time.Second) / time.Second)
	if seconds < 3600 {
		return fmt.Sprintf("%02d:%02d", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%02d:%02d:%02d", seconds/3600, (seconds%3600)/60, seconds%60)
}

func networkErrorSummary(err error) string {
	if err == nil {
		return ""
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) {
			return "TCP connection masofaviy tomon tomonidan reset qilindi"
		}
		if errors.Is(opErr.Err, syscall.ECONNABORTED) {
			return "TCP connection bekor qilindi"
		}
		if opErr.Timeout() {
			return "network timeout"
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "TCP oqimi transfer tugashidan oldin yopildi"
	}
	return strings.TrimSpace(err.Error())
}

func isRetryableNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
