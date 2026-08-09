package transfer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

const (
	maxResumeAttempts = 8
	initialRetryDelay = 1500 * time.Millisecond
	maxRetryDelay     = 8 * time.Second
)

type ClientConfig struct {
	Addr           string
	TLSConfig      *tls.Config
	ConnectTimeout time.Duration
	IOTimeout      time.Duration

	// OnRoomCreated is optional and mainly useful for embedding/testing the
	// transfer package. The CLI does not need to set it.
	OnRoomCreated func(string)
}

func (c ClientConfig) dial() (net.Conn, error) {
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 10 * time.Second
	}
	if c.IOTimeout <= 0 {
		c.IOTimeout = 2 * time.Hour
	}

	d := net.Dialer{
		Timeout:   c.ConnectTimeout,
		KeepAlive: 20 * time.Second,
	}
	raw, err := d.Dial("tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(20 * time.Second)
		_ = tcp.SetReadBuffer(transferBufferSize)
		_ = tcp.SetWriteBuffer(transferBufferSize)
	}

	if c.TLSConfig == nil {
		return raw, nil
	}

	tlsConn := tls.Client(raw, c.TLSConfig.Clone())
	_ = tlsConn.SetDeadline(time.Now().Add(c.ConnectTimeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
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
	meta := protocol.FileMeta{Name: filepath.Base(path), Size: info.Size(), SHA256: sum}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	room := ""
	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		conn, err := cfg.dial()
		if err != nil {
			if room != "" && attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("serverga qayta ulanish", attempt, err)
				continue
			}
			return room, err
		}

		if cfg.IOTimeout <= 0 {
			cfg.IOTimeout = 2 * time.Hour
		}
		_ = conn.SetDeadline(time.Now().Add(cfg.IOTimeout))

		if room == "" {
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreate, File: &meta})
			if err == nil {
				var created protocol.Message
				created, err = protocol.ReadMessage(conn)
				if err == nil {
					switch {
					case created.Type == protocol.TypeError:
						err = errors.New(created.Text)
					case created.Type != protocol.TypeCreated || created.Room == "":
						err = errors.New("unexpected create response")
					default:
						room = created.Room
						if cfg.OnRoomCreated != nil {
							cfg.OnRoomCreated(room)
						}
						fmt.Printf("\n==============================================\n")
						fmt.Printf(" XONA KODI: %s\n", room)
						fmt.Printf(" Qabul qiluvchiga shu kodni yuboring.\n")
						fmt.Printf("==============================================\n\n")
					}
				}
			}
		} else {
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeResumeSend, Room: room, File: &meta})
			if err == nil {
				var resumed protocol.Message
				resumed, err = protocol.ReadMessage(conn)
				if err == nil {
					switch resumed.Type {
					case protocol.TypeComplete:
						_ = conn.Close()
						return room, nil
					case protocol.TypeError:
						err = errors.New(resumed.Text)
					case protocol.TypeJoined:
						fmt.Printf("[i] Room %s ga qayta ulandi. Resume kutilmoqda...\n", room)
					default:
						err = errors.New("unexpected resume response")
					}
				}
			}
		}

		if err != nil {
			_ = conn.Close()
			if room != "" && attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("sender reconnect", attempt, err)
				continue
			}
			return room, err
		}

		ready, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("receiver kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return room, err
		}
		if ready.Type == protocol.TypeComplete {
			_ = conn.Close()
			return room, nil
		}
		if ready.Type == protocol.TypeError {
			_ = conn.Close()
			return room, errors.New(ready.Text)
		}
		if ready.Type != protocol.TypePeerReady {
			_ = conn.Close()
			return room, errors.New("unexpected peer-ready response")
		}

		offset := ready.Offset
		if offset < 0 || offset > meta.Size {
			_ = conn.Close()
			return room, fmt.Errorf("server returned invalid resume offset: %d", offset)
		}
		if offset > 0 {
			fmt.Printf("[↻] Resume: %s dan davom etadi (%5.2f%%)\n", HumanBytes(offset), percentage(offset, meta.Size))
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = conn.Close()
			return room, err
		}

		progress := NewProgressWriter("Yuborish", meta.Size, offset)
		buf, put := getTransferBuffer()
		remaining := meta.Size - offset
		written, copyErr := io.CopyBuffer(io.MultiWriter(conn, progress), io.LimitReader(f, remaining), *buf)
		put()
		progress.Finish()

		if copyErr != nil || written != remaining {
			if copyErr == nil {
				copyErr = fmt.Errorf("short send: %d/%d bytes", written, remaining)
			}
			done, elapsed, avg := progress.Snapshot()
			fmt.Printf("[!] Transfer uzildi: %s / %s | %s | o'rtacha %s/s\n",
				HumanBytes(done), HumanBytes(meta.Size), HumanDuration(elapsed), HumanBytes(int64(avg)))
			fmt.Printf("[!] Sabab: %s\n", networkErrorSummary(copyErr))
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(copyErr) {
				printRetry("avtomatik resume", attempt, copyErr)
				continue
			}
			return room, copyErr
		}

		result, err := protocol.ReadMessage(conn)
		_ = conn.Close()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("tasdiq kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return room, err
		}
		if result.Type == protocol.TypeComplete {
			return room, nil
		}
		if result.Type == protocol.TypeError {
			return room, errors.New(result.Text)
		}
		return room, errors.New("transfer completion was not confirmed")
	}

	return room, errors.New("resume attempts exhausted")
}

func ReceiveFile(cfg ClientConfig, room, outputDir string) (string, error) {
	room = strings.ToUpper(strings.TrimSpace(room))
	if room == "" {
		return "", errors.New("room code required")
	}
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	tmpPath := filepath.Join(outputDir, ".protransfer-"+room+".part")
	var expectedMeta *protocol.FileMeta

	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		conn, err := cfg.dial()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("serverga qayta ulanish", attempt, err)
				continue
			}
			return "", err
		}
		if cfg.IOTimeout <= 0 {
			cfg.IOTimeout = 2 * time.Hour
		}
		_ = conn.SetDeadline(time.Now().Add(cfg.IOTimeout))

		msgType := protocol.TypeJoin
		if expectedMeta != nil {
			msgType = protocol.TypeResumeReceive
		}
		if err := protocol.WriteMessage(conn, protocol.Message{Type: msgType, Room: room}); err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("receiver reconnect", attempt, err)
				continue
			}
			return "", err
		}

		joined, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("join javobida connection uzildi", attempt, err)
				continue
			}
			return "", err
		}
		if joined.Type == protocol.TypeComplete {
			_ = conn.Close()
			// This can happen only if the previous connection completed and the
			// acknowledgement was lost. The .part file is finalized below after
			// metadata has been seen in a previous attempt.
			if expectedMeta == nil {
				return "", errors.New("server reports complete but local metadata is missing")
			}
			return finalizeReceivedFile(tmpPath, outputDir, *expectedMeta)
		}
		if joined.Type == protocol.TypeError {
			_ = conn.Close()
			return "", errors.New(joined.Text)
		}
		if joined.Type != protocol.TypeJoined || joined.File == nil {
			_ = conn.Close()
			return "", errors.New("invalid join response")
		}
		meta := *joined.File
		if meta.Size < 0 || len(meta.SHA256) != 64 {
			_ = conn.Close()
			return "", errors.New("invalid file metadata values")
		}
		if expectedMeta != nil && (expectedMeta.Size != meta.Size || expectedMeta.SHA256 != meta.SHA256 || expectedMeta.Name != meta.Name) {
			_ = conn.Close()
			return "", errors.New("room metadata changed during resume")
		}
		expectedMeta = &meta

		part, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			_ = conn.Close()
			return "", err
		}
		st, err := part.Stat()
		if err != nil {
			_ = part.Close()
			_ = conn.Close()
			return "", err
		}
		offset := st.Size()
		if offset < 0 || offset > meta.Size {
			if err := part.Truncate(0); err != nil {
				_ = part.Close()
				_ = conn.Close()
				return "", err
			}
			offset = 0
		}

		if attempt == 0 {
			fmt.Printf("[i] Fayl: %s | Hajmi: %s\n", SafeFilename(meta.Name), HumanBytes(meta.Size))
		} else {
			fmt.Printf("[↻] Receiver resume: lokal .part = %s (%5.2f%%)\n", HumanBytes(offset), percentage(offset, meta.Size))
		}

		if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeReceiverReady, Room: room, Offset: offset}); err != nil {
			_ = part.Close()
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("resume offset yuborishda uzildi", attempt, err)
				continue
			}
			return "", err
		}

		ready, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = part.Close()
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("sender kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return "", err
		}
		if ready.Type == protocol.TypeComplete {
			_ = part.Close()
			_ = conn.Close()
			return finalizeReceivedFile(tmpPath, outputDir, meta)
		}
		if ready.Type == protocol.TypeError {
			_ = part.Close()
			_ = conn.Close()
			return "", errors.New(ready.Text)
		}
		if ready.Type != protocol.TypePeerReady {
			_ = part.Close()
			_ = conn.Close()
			return "", errors.New("unexpected peer-ready response")
		}
		if ready.Offset < 0 || ready.Offset > offset {
			_ = part.Close()
			_ = conn.Close()
			return "", fmt.Errorf("server returned invalid receive offset: %d (local=%d)", ready.Offset, offset)
		}
		if ready.Offset != offset {
			if err := part.Truncate(ready.Offset); err != nil {
				_ = part.Close()
				_ = conn.Close()
				return "", err
			}
			offset = ready.Offset
		}
		if _, err := part.Seek(offset, io.SeekStart); err != nil {
			_ = part.Close()
			_ = conn.Close()
			return "", err
		}

		progress := NewProgressWriter("Qabul qilish", meta.Size, offset)
		buf, put := getTransferBuffer()
		remaining := meta.Size - offset
		written, copyErr := io.CopyBuffer(io.MultiWriter(part, progress), io.LimitReader(conn, remaining), *buf)
		put()
		progress.Finish()

		if copyErr != nil || written != remaining {
			if copyErr == nil {
				copyErr = fmt.Errorf("receive interrupted after %d/%d bytes: %w", written, remaining, io.ErrUnexpectedEOF)
			}
			_ = part.Sync()
			_ = part.Close()
			_ = conn.Close()
			done, elapsed, avg := progress.Snapshot()
			fmt.Printf("[!] Qabul uzildi: %s / %s | %s | o'rtacha %s/s\n",
				HumanBytes(done), HumanBytes(meta.Size), HumanDuration(elapsed), HumanBytes(int64(avg)))
			fmt.Printf("[!] Sabab: %s\n", networkErrorSummary(copyErr))
			if attempt < maxResumeAttempts && isRetryableNetworkError(copyErr) {
				printRetry("avtomatik resume", attempt, copyErr)
				continue
			}
			return "", copyErr
		}

		if err := part.Sync(); err != nil {
			_ = part.Close()
			_ = conn.Close()
			return "", err
		}
		if err := part.Close(); err != nil {
			_ = conn.Close()
			return "", err
		}

		fmt.Println("[i] SHA-256 tekshirilmoqda...")
		actualHash, err := FileSHA256(tmpPath)
		if err != nil {
			_ = conn.Close()
			return "", err
		}
		if actualHash != meta.SHA256 {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Room: room, Text: "sha256 mismatch"})
			_ = conn.Close()
			_ = os.Remove(tmpPath)
			return "", fmt.Errorf("sha256 mismatch: expected %s, got %s", meta.SHA256, actualHash)
		}
		if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeVerified, Room: room}); err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("verify tasdig'ida connection uzildi", attempt, err)
				continue
			}
			return "", err
		}

		result, err := protocol.ReadMessage(conn)
		_ = conn.Close()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("yakuniy tasdiqda connection uzildi", attempt, err)
				continue
			}
			return "", err
		}
		if result.Type == protocol.TypeError {
			return "", errors.New(result.Text)
		}
		if result.Type != protocol.TypeComplete {
			return "", errors.New("transfer completion was not confirmed")
		}
		return finalizeReceivedFile(tmpPath, outputDir, meta)
	}

	return "", errors.New("resume attempts exhausted")
}

func finalizeReceivedFile(tmpPath, outputDir string, meta protocol.FileMeta) (string, error) {
	st, err := os.Stat(tmpPath)
	if err != nil {
		return "", err
	}
	if st.Size() != meta.Size {
		return "", fmt.Errorf("partial file size mismatch: have %d, expected %d", st.Size(), meta.Size)
	}
	finalPath := uniquePath(filepath.Join(outputDir, SafeFilename(meta.Name)))
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
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

func percentage(done, total int64) float64 {
	if total <= 0 {
		return 100
	}
	return float64(done) * 100 / float64(total)
}

func printRetry(action string, attempt int, err error) {
	delay := initialRetryDelay << min(attempt, 3)
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	fmt.Printf("[↻] %s: %s. %s dan keyin qayta uriniladi (%d/%d)...\n",
		action, networkErrorSummary(err), delay.Round(time.Millisecond), attempt+1, maxResumeAttempts)
	time.Sleep(delay)
}
