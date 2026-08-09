package transfer

import (
	"crypto/cipher"
	"crypto/rand"
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

	OnRoomCreated  func(string)
	OnTransferCode func(string)
}

func (c ClientConfig) dial() (net.Conn, error) {
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 10 * time.Second
	}
	if c.IOTimeout <= 0 {
		c.IOTimeout = 2 * time.Hour
	}
	d := net.Dialer{Timeout: c.ConnectTimeout, KeepAlive: 20 * time.Second}
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

func SendPaths(cfg ClientConfig, inputs []string) (string, error) {
	manifest, sources, err := buildManifest(inputs)
	if err != nil {
		return "", err
	}
	fileCount, dirCount := manifestCounts(manifest)
	fmt.Printf("[i] %d ta fayl, %d ta folder | Jami: %s\n", fileCount, dirCount, HumanBytes(manifest.TotalSize))

	manifestJSON, err := marshalManifest(manifest)
	if err != nil {
		return "", err
	}
	secret, err := generateTransferSecret()
	if err != nil {
		return "", err
	}
	encryptedManifest, err := encryptManifest(secret, manifestJSON)
	if err != nil {
		return "", err
	}
	dataAEAD, err := newAEAD(secret, "data-key")
	if err != nil {
		return "", err
	}
	plans, payloadSize, err := buildChunkPlan(manifest, sources, dataAEAD.Overhead()+dataAEAD.NonceSize())
	if err != nil {
		return "", err
	}
	session := protocol.SessionMeta{
		TransferID: transferID(encryptedManifest), PlainSize: manifest.TotalSize,
		PayloadSize: payloadSize, EncryptedManifest: encryptedManifest,
	}
	if len(encryptedManifest) > protocol.MaxFrameSize/2 {
		return "", fmt.Errorf("encrypted manifest juda katta: %s", HumanBytes(int64(len(encryptedManifest))))
	}

	room := ""
	code := ""
	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		conn, err := cfg.dial()
		if err != nil {
			if room != "" && attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("serverga qayta ulanish", attempt, err)
				continue
			}
			return code, err
		}
		_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))

		if room == "" {
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreate, Session: &session})
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
						code = encodeTransferCode(room, secret)
						if cfg.OnRoomCreated != nil {
							cfg.OnRoomCreated(room)
						}
						if cfg.OnTransferCode != nil {
							cfg.OnTransferCode(code)
						}
						fmt.Printf("\n==============================================================\n")
						fmt.Printf(" TRANSFER CODE:\n %s\n", code)
						fmt.Printf("==============================================================\n")
						fmt.Println("[🔒] End-to-end encryption: AES-256-GCM")
						fmt.Println("[i] To'liq code'ni qabul qiluvchiga bering; SECRET serverga yuborilmaydi.")
						fmt.Println()
					}
				}
			}
		} else {
			resumeMeta := session
			resumeMeta.EncryptedManifest = nil
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeResumeSend, Room: room, Session: &resumeMeta})
			if err == nil {
				var resumed protocol.Message
				resumed, err = protocol.ReadMessage(conn)
				if err == nil {
					switch resumed.Type {
					case protocol.TypeComplete:
						_ = conn.Close()
						return code, nil
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
			return code, err
		}

		ready, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("receiver kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return code, err
		}
		if ready.Type == protocol.TypeComplete {
			_ = conn.Close()
			return code, nil
		}
		if ready.Type == protocol.TypeError {
			_ = conn.Close()
			return code, errors.New(ready.Text)
		}
		if ready.Type != protocol.TypePeerReady {
			_ = conn.Close()
			return code, errors.New("unexpected peer-ready response")
		}

		planIndex, err := chunkIndexForCipherOffset(plans, session.PayloadSize, ready.Offset)
		if err != nil {
			_ = conn.Close()
			return code, err
		}
		plainBase := plainDoneAtPlanIndex(plans, planIndex, manifest.TotalSize)
		if ready.Offset > 0 {
			fmt.Printf("[↻] Resume: %s dan davom etadi (%5.2f%%)\n", HumanBytes(plainBase), percentage(plainBase, manifest.TotalSize))
		}

		progress := NewProgressWriter("Yuborish", manifest.TotalSize, plainBase)
		sendErr := sendEncryptedChunks(conn, dataAEAD, plans, planIndex, progress)
		progress.Finish()
		if sendErr != nil {
			done, elapsed, avg := progress.Snapshot()
			fmt.Printf("[!] Transfer uzildi: %s / %s | %s | o'rtacha %s/s\n",
				HumanBytes(done), HumanBytes(manifest.TotalSize), HumanDuration(elapsed), HumanBytes(int64(avg)))
			fmt.Printf("[!] Sabab: %s\n", networkErrorSummary(sendErr))
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(sendErr) {
				printRetry("avtomatik resume", attempt, sendErr)
				continue
			}
			return code, sendErr
		}

		result, err := protocol.ReadMessage(conn)
		_ = conn.Close()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("tasdiq kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return code, err
		}
		if result.Type == protocol.TypeComplete {
			return code, nil
		}
		if result.Type == protocol.TypeError {
			return code, errors.New(result.Text)
		}
		return code, errors.New("transfer completion was not confirmed")
	}
	return code, errors.New("resume attempts exhausted")
}

func sendEncryptedChunks(conn net.Conn, aead cipher.AEAD, plans []chunkPlan, start int, progress *ProgressWriter) error {
	var currentPath string
	var f *os.File
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	plainBuf := make([]byte, defaultChunkSize)
	cipherBuf := make([]byte, 0, defaultChunkSize+aead.Overhead())

	for i := start; i < len(plans); i++ {
		p := plans[i]
		if p.LocalPath == "" {
			return fmt.Errorf("source mapping topilmadi: %s", p.ManifestPath)
		}
		if currentPath != p.LocalPath {
			if f != nil {
				_ = f.Close()
			}
			var err error
			f, err = os.Open(p.LocalPath)
			if err != nil {
				return err
			}
			currentPath = p.LocalPath
		}
		if _, err := f.Seek(p.FileOffset, io.SeekStart); err != nil {
			return err
		}
		plain := plainBuf[:p.PlainSize]
		if _, err := io.ReadFull(f, plain); err != nil {
			return fmt.Errorf("source file transfer paytida o'zgargan yoki o'qilmadi (%s): %w", p.ManifestPath, err)
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		sealed := aead.Seal(cipherBuf[:0], nonce, plain, chunkAAD(p.Index, p.PlainSize))
		record := make([]byte, 0, len(nonce)+len(sealed))
		record = append(record, nonce...)
		record = append(record, sealed...)
		if int64(len(record)) != p.CipherSize {
			return errors.New("internal encrypted chunk size mismatch")
		}
		if err := writeAll(conn, record); err != nil {
			return err
		}
		progress.Add(int64(p.PlainSize))
	}
	return nil
}

func ReceiveTransfer(cfg ClientConfig, transferCode, outputDir string) ([]string, error) {
	room, secret, err := parseTransferCode(transferCode)
	if err != nil {
		return nil, err
	}
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	var session *protocol.SessionMeta
	var manifest Manifest
	var plans []chunkPlan
	var dataAEAD cipher.AEAD
	var staging *receiverStaging

	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		conn, err := cfg.dial()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("serverga qayta ulanish", attempt, err)
				continue
			}
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))

		msgType := protocol.TypeJoin
		if session != nil {
			msgType = protocol.TypeResumeReceive
		}
		if err := protocol.WriteMessage(conn, protocol.Message{Type: msgType, Room: room}); err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("receiver reconnect", attempt, err)
				continue
			}
			return nil, err
		}

		joined, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("join javobida connection uzildi", attempt, err)
				continue
			}
			return nil, err
		}
		if joined.Type == protocol.TypeComplete {
			_ = conn.Close()
			if staging == nil || session == nil {
				return nil, errors.New("server complete dedi, lekin lokal resume state topilmadi")
			}
			if err := verifyStaging(staging.contentDir, manifest); err != nil {
				return nil, err
			}
			return finalizeStaging(staging, outputDir, manifest)
		}
		if joined.Type == protocol.TypeError {
			_ = conn.Close()
			return nil, errors.New(joined.Text)
		}
		if joined.Type != protocol.TypeJoined || joined.Session == nil {
			_ = conn.Close()
			return nil, errors.New("unexpected join response")
		}

		if session == nil {
			s := *joined.Session
			if transferID(s.EncryptedManifest) != s.TransferID {
				_ = conn.Close()
				return nil, errors.New("encrypted manifest transfer_id mismatch")
			}
			plainManifest, err := decryptManifest(secret, s.EncryptedManifest)
			if err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("SECRET noto'g'ri yoki manifest buzilgan: %w", err)
			}
			manifest, err = unmarshalManifest(plainManifest)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if manifest.TotalSize != s.PlainSize {
				_ = conn.Close()
				return nil, errors.New("session plain_size manifest bilan mos emas")
			}
			dataAEAD, err = newAEAD(secret, "data-key")
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			var payloadSize int64
			plans, payloadSize, err = buildChunkPlan(manifest, nil, dataAEAD.Overhead()+dataAEAD.NonceSize())
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if payloadSize != s.PayloadSize {
				_ = conn.Close()
				return nil, errors.New("session payload_size manifest bilan mos emas")
			}
			session = &s
			files, dirs := manifestCounts(manifest)
			fmt.Printf("[i] %d ta fayl, %d ta folder | Jami: %s\n", files, dirs, HumanBytes(manifest.TotalSize))
			fmt.Println("[🔒] End-to-end encryption tasdiqlandi. Manifest decrypt qilindi.")
		} else if joined.Session.TransferID != session.TransferID || joined.Session.PayloadSize != session.PayloadSize || joined.Session.PlainSize != session.PlainSize {
			_ = conn.Close()
			return nil, errors.New("resume session original transfer bilan mos emas")
		}

		staging, _, err = openReceiverStaging(outputDir, room, session.TransferID, manifest, plans, session.PayloadSize)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		planIndex, err := chunkIndexForCipherOffset(plans, session.PayloadSize, staging.state.CipherOffset)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		plainBase := plainDoneAtPlanIndex(plans, planIndex, manifest.TotalSize)
		if staging.state.CipherOffset > 0 {
			fmt.Printf("[↻] Receiver resume: lokal state = %s (%5.2f%%)\n", HumanBytes(plainBase), percentage(plainBase, manifest.TotalSize))
		}

		if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeReceiverReady, Room: room, Offset: staging.state.CipherOffset}); err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("receiver ready yuborishda connection uzildi", attempt, err)
				continue
			}
			return nil, err
		}

		ready, err := protocol.ReadMessage(conn)
		if err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("sender kutilayotganda connection uzildi", attempt, err)
				continue
			}
			return nil, err
		}
		if ready.Type == protocol.TypeComplete {
			_ = conn.Close()
			if err := verifyStaging(staging.contentDir, manifest); err != nil {
				return nil, err
			}
			return finalizeStaging(staging, outputDir, manifest)
		}
		if ready.Type == protocol.TypeError {
			_ = conn.Close()
			return nil, errors.New(ready.Text)
		}
		if ready.Type != protocol.TypePeerReady || ready.Offset != staging.state.CipherOffset {
			_ = conn.Close()
			return nil, errors.New("server noto'g'ri resume offset qaytardi")
		}

		progress := NewProgressWriter("Qabul qilish", manifest.TotalSize, plainBase)
		recvErr := receiveEncryptedChunks(conn, dataAEAD, staging, plans, planIndex, progress)
		progress.Finish()
		if recvErr != nil {
			done, elapsed, avg := progress.Snapshot()
			fmt.Printf("[!] Qabul uzildi: %s / %s | %s | o'rtacha %s/s\n",
				HumanBytes(done), HumanBytes(manifest.TotalSize), HumanDuration(elapsed), HumanBytes(int64(avg)))
			fmt.Printf("[!] Sabab: %s\n", networkErrorSummary(recvErr))
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(recvErr) {
				printRetry("avtomatik resume", attempt, recvErr)
				continue
			}
			return nil, recvErr
		}

		fmt.Println("[i] Barcha fayllar SHA-256 bo'yicha tekshirilmoqda...")
		if err := verifyStaging(staging.contentDir, manifest); err != nil {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Room: room, Text: "integrity verification failed"})
			_ = conn.Close()
			return nil, err
		}
		if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeVerified, Room: room}); err != nil {
			_ = conn.Close()
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("verify tasdig'ida connection uzildi", attempt, err)
				continue
			}
			return nil, err
		}
		result, err := protocol.ReadMessage(conn)
		_ = conn.Close()
		if err != nil {
			if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("yakuniy tasdiqda connection uzildi", attempt, err)
				continue
			}
			return nil, err
		}
		if result.Type == protocol.TypeError {
			return nil, errors.New(result.Text)
		}
		if result.Type != protocol.TypeComplete {
			return nil, errors.New("transfer completion was not confirmed")
		}
		return finalizeStaging(staging, outputDir, manifest)
	}
	return nil, errors.New("resume attempts exhausted")
}

func receiveEncryptedChunks(conn net.Conn, aead cipher.AEAD, staging *receiverStaging, plans []chunkPlan, start int, progress *ProgressWriter) error {
	maxCipherSize := aead.Overhead()
	for _, p := range plans {
		if int(p.CipherSize) > maxCipherSize {
			maxCipherSize = int(p.CipherSize)
		}
	}
	cipherBuf := make([]byte, maxCipherSize)
	var currentPath string
	var f *os.File
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	for i := start; i < len(plans); i++ {
		p := plans[i]
		ciphertext := cipherBuf[:int(p.CipherSize)]
		if _, err := io.ReadFull(conn, ciphertext); err != nil {
			return err
		}
		if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
			return errors.New("encrypted chunk record juda qisqa")
		}
		nonce := ciphertext[:aead.NonceSize()]
		sealed := ciphertext[aead.NonceSize():]
		plaintext, err := aead.Open(nil, nonce, sealed, chunkAAD(p.Index, p.PlainSize))
		if err != nil {
			return fmt.Errorf("encrypted chunk authentication failed (#%d): %w", p.Index, err)
		}
		if len(plaintext) != p.PlainSize {
			return errors.New("decrypted chunk size mismatch")
		}

		target, err := safeOutputPath(staging.contentDir, p.ManifestPath)
		if err != nil {
			return err
		}
		if currentPath != target {
			if f != nil {
				_ = f.Close()
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err = os.OpenFile(target, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				return err
			}
			currentPath = target
		}
		if _, err := f.WriteAt(plaintext, p.FileOffset); err != nil {
			return err
		}
		nextOffset := p.CipherOffset + p.CipherSize
		if err := staging.commitOffset(nextOffset); err != nil {
			return err
		}
		progress.Add(int64(p.PlainSize))
	}
	return nil
}

func SendFile(cfg ClientConfig, path string) (string, error) {
	return SendPaths(cfg, []string{path})
}

func ReceiveFile(cfg ClientConfig, transferCode, outputDir string) (string, error) {
	paths, err := ReceiveTransfer(cfg, transferCode, outputDir)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return outputDir, nil
	}
	return paths[0], nil
}

func effectiveIOTimeout(cfg ClientConfig) time.Duration {
	if cfg.IOTimeout <= 0 {
		return 2 * time.Hour
	}
	return cfg.IOTimeout
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

func manifestCounts(m Manifest) (files, dirs int) {
	for _, e := range m.Entries {
		if e.Type == "file" {
			files++
		} else if e.Type == "dir" {
			dirs++
		}
	}
	return
}

func normalizeInputs(inputs []string) []string {
	out := make([]string, 0, len(inputs))
	for _, p := range inputs {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
