package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
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
	Total     int64
	Done      int64
	LastPrint time.Time
	Label     string
}

func (p *ProgressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.Done += int64(n)
	now := time.Now()
	if p.LastPrint.IsZero() || now.Sub(p.LastPrint) >= 500*time.Millisecond || p.Done == p.Total {
		pct := float64(0)
		if p.Total > 0 {
			pct = float64(p.Done) * 100 / float64(p.Total)
		}
		fmt.Printf("\r%s: %6.2f%%  %s / %s", p.Label, pct, HumanBytes(p.Done), HumanBytes(p.Total))
		p.LastPrint = now
		if p.Done == p.Total {
			fmt.Println()
		}
	}
	return n, nil
}

func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
