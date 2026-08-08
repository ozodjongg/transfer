package transfer

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

type ClientConfig struct {
	Addr           string
	TLSConfig      *tls.Config
	ConnectTimeout time.Duration
	IOTimeout      time.Duration
}

func (c ClientConfig) dial() (net.Conn, error) {
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 10 * time.Second
	}
	if c.IOTimeout <= 0 {
		c.IOTimeout = 2 * time.Hour
	}
	d := net.Dialer{Timeout: c.ConnectTimeout}
	if c.TLSConfig != nil {
		return tls.DialWithDialer(&d, "tcp", c.Addr, c.TLSConfig)
	}
	return d.Dial("tcp", c.Addr)
}

func SendFile(cfg ClientConfig, path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("selected path is not a regular file")
	}

	fmt.Println("[i] SHA-256 hisoblanmoqda...")
	sum, err := FileSHA256(path)
	if err != nil {
		return "", err
	}

	conn, err := cfg.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = 2 * time.Hour
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.IOTimeout))

	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreate}); err != nil {
		return "", err
	}
	created, err := protocol.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	if created.Type == protocol.TypeError {
		return "", errors.New(created.Text)
	}
	if created.Type != protocol.TypeCreated || created.Room == "" {
		return "", errors.New("unexpected create response")
	}

	room := created.Room
	fmt.Printf("\n==============================================\n")
	fmt.Printf(" XONA KODI: %s\n", room)
	fmt.Printf(" Qabul qiluvchiga shu kodni yuboring.\n")
	fmt.Printf("==============================================\n\n")

	ready, err := protocol.ReadMessage(conn)
	if err != nil {
		return room, err
	}
	if ready.Type == protocol.TypeError {
		return room, errors.New(ready.Text)
	}
	if ready.Type != protocol.TypePeerReady {
		return room, errors.New("unexpected peer-ready response")
	}

	f, err := os.Open(path)
	if err != nil {
		return room, err
	}
	defer f.Close()

	meta := protocol.FileMeta{Name: filepath.Base(path), Size: info.Size(), SHA256: sum}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeFileMeta, File: &meta}); err != nil {
		return room, err
	}

	progress := &ProgressWriter{Total: info.Size(), Label: "Yuborish"}
	written, err := io.Copy(io.MultiWriter(conn, progress), f)
	if err != nil {
		return room, err
	}
	if written != info.Size() {
		return room, fmt.Errorf("short send: %d/%d bytes", written, info.Size())
	}

	result, err := protocol.ReadMessage(conn)
	if err != nil {
		return room, err
	}
	if result.Type == protocol.TypeError {
		return room, errors.New(result.Text)
	}
	if result.Type != protocol.TypeComplete {
		return room, errors.New("transfer completion was not confirmed")
	}
	return room, nil
}

func ReceiveFile(cfg ClientConfig, room, outputDir string) (string, error) {
	conn, err := cfg.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = 2 * time.Hour
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.IOTimeout))

	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeJoin, Room: room}); err != nil {
		return "", err
	}
	joined, err := protocol.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	if joined.Type == protocol.TypeError {
		return "", errors.New(joined.Text)
	}
	if joined.Type != protocol.TypeJoined {
		return "", errors.New("unexpected join response")
	}

	metaMsg, err := protocol.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	if metaMsg.Type == protocol.TypeError {
		return "", errors.New(metaMsg.Text)
	}
	if metaMsg.Type != protocol.TypeFileMeta || metaMsg.File == nil {
		return "", errors.New("invalid file metadata")
	}
	meta := metaMsg.File
	if meta.Size < 0 || len(meta.SHA256) != 64 {
		return "", errors.New("invalid file metadata values")
	}

	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	name := SafeFilename(meta.Name)
	finalPath := uniquePath(filepath.Join(outputDir, name))
	tmp, err := os.CreateTemp(outputDir, ".transfer-*.part")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	fmt.Printf("[i] Fayl: %s | Hajmi: %s\n", name, HumanBytes(meta.Size))
	h := sha256.New()
	progress := &ProgressWriter{Total: meta.Size, Label: "Qabul qilish"}
	written, err := io.CopyN(io.MultiWriter(tmp, h, progress), conn, meta.Size)
	if err != nil {
		return "", fmt.Errorf("receive interrupted after %d/%d bytes: %w", written, meta.Size, err)
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != meta.SHA256 {
		return "", fmt.Errorf("sha256 mismatch: expected %s, got %s", meta.SHA256, actualHash)
	}

	result, err := protocol.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	if result.Type == protocol.TypeError {
		return "", errors.New(result.Text)
	}
	if result.Type != protocol.TypeComplete {
		return "", errors.New("transfer completion was not confirmed")
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	committed = true
	return finalPath, nil
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}
