package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const transferBufferSize = 1024 * 1024 // 1 MiB

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

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	buf, put := getTransferBuffer()
	defer put()
	if _, err := io.CopyBuffer(h, f, *buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func SafeFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "\x00", "")
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "received_file"
	}
	return name
}

type ProgressWriter struct {
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
		Total:      total,
		Done:       baseOffset,
		BaseOffset: baseOffset,
		Label:      label,
		startedAt:  now,
		lastPrint:  now,
		lastDone:   baseOffset,
	}
}

func (p *ProgressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.Done += int64(n)
	now := time.Now()
	if now.Sub(p.lastPrint) >= 500*time.Millisecond || p.Done >= p.Total {
		p.print(now)
	}
	return n, nil
}

func (p *ProgressWriter) print(now time.Time) {
	elapsedSample := now.Sub(p.lastPrint).Seconds()
	if elapsedSample > 0 {
		instant := float64(p.Done-p.lastDone) / elapsedSample
		if p.emaBytesPS == 0 {
			p.emaBytesPS = instant
		} else {
			p.emaBytesPS = p.emaBytesPS*0.70 + instant*0.30
		}
	}

	pct := 0.0
	if p.Total > 0 {
		pct = float64(p.Done) * 100 / float64(p.Total)
	}

	eta := "--:--"
	if p.emaBytesPS > 1 && p.Done < p.Total {
		remaining := float64(p.Total-p.Done) / p.emaBytesPS
		eta = HumanDuration(time.Duration(remaining * float64(time.Second)))
	} else if p.Done >= p.Total {
		eta = "00:00"
	}

	fmt.Printf("\r%-13s %6.2f%% | %s / %s | %s/s | ETA %s",
		p.Label+":", pct, HumanBytes(p.Done), HumanBytes(p.Total), HumanBytes(int64(p.emaBytesPS)), eta)

	p.lastPrint = now
	p.lastDone = p.Done
	p.printed = true
}

func (p *ProgressWriter) Finish() {
	if !p.printed || p.lastDone != p.Done {
		p.print(time.Now())
	}
	if p.printed {
		fmt.Println()
	}
}

func (p *ProgressWriter) Snapshot() (done int64, elapsed time.Duration, avgBytesPerSecond float64) {
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
	return err.Error()
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
	// Windows/Linux reset/abort errors are usually wrapped by net.OpError.
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}
