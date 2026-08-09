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
	Addr            string
	TLSConfig       *tls.Config
	ConnectTimeout  time.Duration
	IOTimeout       time.Duration
	LANDirect       bool
	ParallelStreams int

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

	phrase, err := generateCodePhrase()
	if err != nil {
		return "", err
	}
	room, err := roomFromCodePhrase(phrase)
	if err != nil {
		return "", err
	}
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
	resumeRooms := deriveResumeRooms(secret, maxResumeAttempts)
	streamCount := cfg.ParallelStreams
	if streamCount < 1 {
		streamCount = 1
	}
	if streamCount > maxParallelStreams {
		streamCount = maxParallelStreams
	}
	ranges := splitPlanRanges(plans, streamCount)
	attachToken := deriveAttachToken(secret)
	session := protocol.SessionMeta{
		TransferID: transferID(encryptedManifest), PlainSize: manifest.TotalSize,
		PayloadSize: payloadSize, EncryptedManifest: encryptedManifest, ResumeRooms: resumeRooms,
		StreamCount: len(ranges), StreamPayloadSizes: streamPayloadSizes(ranges), AttachToken: attachToken,
	}
	if len(encryptedManifest) > protocol.MaxFrameSize/2 {
		return "", fmt.Errorf("encrypted manifest juda katta: %s", HumanBytes(int64(len(encryptedManifest))))
	}

	// V7: LAN candidates are NOT embedded in the user-visible code. They are
	// delivered only after PAKE succeeds, inside the PAKE-authenticated secret
	// envelope. The public relay therefore sees neither the phrase nor LAN IPs.
	var direct *directSender
	var routes []string
	if cfg.LANDirect {
		directSession := cloneSession(session)
		directSession.StreamCount = 1
		directSession.StreamPayloadSizes = []int64{payloadSize}
		directSession.AttachToken = ""
		if d, derr := startDirectSender(secret, directSession, dataAEAD, plans, manifest.TotalSize); derr == nil {
			candidates := localRouteCandidates(d.Port())
			if len(candidates) > 0 {
				direct = d
				routes = candidates
				direct.SetRoom(room)
			} else {
				d.Close()
			}
		}
	}
	if direct != nil {
		defer direct.Close()
	}
	directStarted := false
	publicSelected := false
	created := false
	pakeDone := false
	code := phrase

	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		conn, err := cfg.dial()
		if err != nil {
			if created && attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("serverga qayta ulanish", attempt, err)
				continue
			}
			return code, err
		}
		_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))

		if !created {
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreate, Room: room, Session: &session})
			if err == nil {
				var createdMsg protocol.Message
				createdMsg, err = protocol.ReadMessage(conn)
				if err == nil {
					switch {
					case createdMsg.Type == protocol.TypeError:
						err = errors.New(createdMsg.Text)
					case createdMsg.Type != protocol.TypeCreated || createdMsg.Room != room:
						err = errors.New("unexpected create response")
					default:
						created = true
						if direct != nil && !directStarted {
							directStarted = true
							go direct.Serve()
						}
						if cfg.OnRoomCreated != nil {
							cfg.OnRoomCreated(room)
						}
						if cfg.OnTransferCode != nil {
							cfg.OnTransferCode(code)
						}
						fmt.Printf("\n==============================================================\n")
						fmt.Printf(" TRANSFER CODE:\n %s\n", code)
						fmt.Printf("==============================================================\n")
						fmt.Println("[🔐] 4-word PAKE handshake + AES-256-GCM end-to-end encryption")
						if direct != nil {
							fmt.Println("[⚡] LAN direct endpoint tayyor; route PAKE'dan keyin xavfsiz uzatiladi.")
						}
						fmt.Println("[i] Faqat 4-word code'ni qabul qiluvchiga bering; code serverga yuborilmaydi.")
						fmt.Println()
					}
				}
			}
		} else {
			resumeMeta := session
			resumeMeta.EncryptedManifest = nil
			resumeRoom := room
			if attempt > 0 && attempt-1 < len(resumeRooms) {
				resumeRoom = resumeRooms[attempt-1]
			}
			err = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeResumeSend, Room: resumeRoom, Session: &resumeMeta})
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
						fmt.Printf("[i] Secure room %s ga qayta ulandi. Resume kutilmoqda...\n", room)
					default:
						err = errors.New("unexpected resume response")
					}
				}
			}
		}

		if err != nil && !created && strings.Contains(err.Error(), "room collision") && attempt < maxResumeAttempts {
			_ = conn.Close()
			phrase, err = generateCodePhrase()
			if err != nil {
				return code, err
			}
			room, err = roomFromCodePhrase(phrase)
			if err != nil {
				return code, err
			}
			code = phrase
			if direct != nil {
				direct.SetRoom(room)
			}
			continue
		}

		if err == nil && !pakeDone {
			// Receiver initiates PAKE after joining. Only after mutual key
			// confirmation do we wrap the random 256-bit transfer secret and LAN
			// candidates for the receiver.
			err = senderPakeExchange(conn, code, room, session.TransferID, secret, routes)
			if err == nil {
				pakeDone = true
				fmt.Println("[🔐] PAKE tasdiqlandi. Receiver E2E transfer secret'ni xavfsiz oldi.")
			}
		}

		if err != nil {
			_ = conn.Close()
			if created && attempt < maxResumeAttempts && isRetryableNetworkError(err) {
				printRetry("sender secure reconnect", attempt, err)
				continue
			}
			return code, err
		}

		var ready protocol.Message
		if direct != nil && !publicSelected {
			type readyResult struct {
				msg protocol.Message
				err error
			}
			readyCh := make(chan readyResult, 1)
			go func(c net.Conn) {
				m, e := protocol.ReadMessage(c)
				readyCh <- readyResult{m, e}
			}(conn)
			select {
			case <-direct.selected:
				fmt.Println("[⚡] LAN direct route tanlandi. Public relay payload uchun ishlatilmaydi.")
				_ = conn.Close()
				go cancelPublicRoom(cfg, room, session.AttachToken)
				directErr := <-direct.done
				if directErr == nil {
					return code, nil
				}
				return code, directErr
			case rr := <-readyCh:
				ready, err = rr.msg, rr.err
				if err == nil {
					publicSelected = true
					direct.Close()
				}
			}
		} else {
			ready, err = protocol.ReadMessage(conn)
		}
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

		var sendErr error
		var progress *ProgressWriter
		if session.StreamCount > 1 {
			if len(ready.Offsets) != session.StreamCount {
				_ = conn.Close()
				return code, errors.New("server stream resume offset count noto'g'ri")
			}
			plainBase := int64(0)
			for i, r := range ranges {
				done, e := streamPlainDone(plans, r, ready.Offsets[i])
				if e != nil {
					_ = conn.Close()
					return code, e
				}
				plainBase += done
			}
			if plainBase > 0 {
				fmt.Printf("[↻] Parallel resume: %s dan davom etadi (%5.2f%%) | %d stream\n", HumanBytes(plainBase), percentage(plainBase, manifest.TotalSize), session.StreamCount)
			} else {
				fmt.Printf("[⇶] Public relay: %d parallel TCP stream\n", session.StreamCount)
			}
			progress = NewProgressWriter("Yuborish", manifest.TotalSize, plainBase)
			sendErr = sendPublicStreams(cfg, room, session.AttachToken, dataAEAD, plans, ranges, ready.Offsets, progress)
		} else {
			planIndex, e := chunkIndexForCipherOffset(plans, session.PayloadSize, ready.Offset)
			if e != nil {
				_ = conn.Close()
				return code, e
			}
			plainBase := plainDoneAtPlanIndex(plans, planIndex, manifest.TotalSize)
			if ready.Offset > 0 {
				fmt.Printf("[↻] Resume: %s dan davom etadi (%5.2f%%)\n", HumanBytes(plainBase), percentage(plainBase, manifest.TotalSize))
			}
			progress = NewProgressWriter("Yuborish", manifest.TotalSize, plainBase)
			sendErr = sendEncryptedChunks(conn, dataAEAD, plans, planIndex, progress)
		}
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
	return sendEncryptedChunksRange(conn, aead, plans, start, len(plans), progress)
}

func sendEncryptedChunksRange(conn net.Conn, aead cipher.AEAD, plans []chunkPlan, start, end int, progress *ProgressWriter) error {
	if start < 0 || end < start || end > len(plans) {
		return errors.New("invalid encrypted chunk range")
	}
	var currentPath string
	var f *os.File
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	plainBuf := make([]byte, defaultChunkSize)
	cipherBuf := make([]byte, 0, defaultChunkSize+aead.Overhead())

	for i := start; i < end; i++ {
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
	phrase, err := normalizeCodePhrase(transferCode)
	if err != nil {
		return nil, err
	}
	room, err := roomFromCodePhrase(phrase)
	if err != nil {
		return nil, err
	}
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	var secret []byte
	var routes []string
	var session *protocol.SessionMeta
	var manifest Manifest
	var plans []chunkPlan
	var ranges []planRange
	var dataAEAD cipher.AEAD
	var staging *receiverStaging

	lanMode := false
	lanAnnounced := false

	for attempt := 0; attempt <= maxResumeAttempts; attempt++ {
		var conn net.Conn
		var joined protocol.Message
		var err error
		usingDirect := false

		// Once an initial PAKE handshake selected LAN direct, reconnects stay on
		// LAN so encrypted chunk offsets cannot be mixed across transports.
		if lanMode && cfg.LANDirect && len(routes) > 0 && len(secret) == transferSecretSize {
			var directAddr string
			conn, joined, directAddr, err = tryDirectReceiver(cfg, routes, room, secret, session != nil)
			if err == nil {
				usingDirect = true
				if !lanAnnounced {
					fmt.Printf("[⚡] LAN direct route topildi: %s. Public relay payload uchun ishlatilmaydi.\n", directAddr)
					lanAnnounced = true
				}
			} else {
				if attempt < maxResumeAttempts {
					printRetry("LAN direct reconnect", attempt, err)
					continue
				}
				return nil, err
			}
		}

		if !usingDirect {
			conn, err = cfg.dial()
			if err != nil {
				if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
					printRetry("serverga qayta ulanish", attempt, err)
					continue
				}
				return nil, err
			}
			_ = conn.SetDeadline(time.Now().Add(effectiveIOTimeout(cfg)))

			msgType := protocol.TypeJoin
			joinRoom := room
			if session != nil {
				msgType = protocol.TypeResumeReceive
				resumeRooms := deriveResumeRooms(secret, maxResumeAttempts)
				if attempt > 0 && attempt-1 < len(resumeRooms) {
					joinRoom = resumeRooms[attempt-1]
				}
			}
			if err := protocol.WriteMessage(conn, protocol.Message{Type: msgType, Room: joinRoom}); err != nil {
				_ = conn.Close()
				if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
					printRetry("receiver reconnect", attempt, err)
					continue
				}
				return nil, err
			}
			joined, err = protocol.ReadMessage(conn)
			if err != nil {
				_ = conn.Close()
				if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
					printRetry("join javobida connection uzildi", attempt, err)
					continue
				}
				return nil, err
			}
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

		// Initial public rendezvous performs PAKE before any transfer secret or
		// LAN route is available to the receiver. The four-word code never goes
		// to the relay and is never used directly as an AES key.
		if session == nil && !usingDirect {
			secret, routes, err = receiverPakeExchange(conn, phrase, room, joined.Session.TransferID)
			if err != nil {
				_ = conn.Close()
				if attempt < maxResumeAttempts && isRetryableNetworkError(err) {
					printRetry("PAKE handshake", attempt, err)
					continue
				}
				return nil, err
			}
			fmt.Println("[🔐] PAKE mutual confirmation muvaffaqiyatli. Random E2E transfer secret olindi.")

			// Now that routes arrived inside the PAKE-authenticated envelope, try
			// LAN. If it succeeds, switch the active session to the sender's local
			// single-stream endpoint and close the public control connection.
			if cfg.LANDirect && len(routes) > 0 {
				directConn, directJoined, directAddr, derr := tryDirectReceiver(cfg, routes, room, secret, false)
				if derr == nil {
					_ = conn.Close()
					conn = directConn
					joined = directJoined
					usingDirect = true
					lanMode = true
					if !lanAnnounced {
						fmt.Printf("[⚡] LAN direct route topildi: %s. Public relay payload uchun ishlatilmaydi.\n", directAddr)
						lanAnnounced = true
					}
				}
			}
		}

		if len(secret) != transferSecretSize {
			_ = conn.Close()
			return nil, errors.New("E2E transfer secret mavjud emas")
		}

		// Routing credentials are derived locally from the random transfer secret;
		// relay metadata is never a trust source for these values.
		joined.Session.AttachToken = deriveAttachToken(secret)
		joined.Session.ResumeRooms = nil

		if session == nil {
			s := *joined.Session
			if transferID(s.EncryptedManifest) != s.TransferID {
				_ = conn.Close()
				return nil, errors.New("encrypted manifest transfer_id mismatch")
			}
			plainManifest, err := decryptManifest(secret, s.EncryptedManifest)
			if err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("manifest authentication failed: %w", err)
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
			if s.StreamCount < 1 || s.StreamCount > maxParallelStreams {
				_ = conn.Close()
				return nil, errors.New("session stream_count noto'g'ri")
			}
			ranges = splitPlanRanges(plans, s.StreamCount)
			if len(ranges) != s.StreamCount || len(s.StreamPayloadSizes) != s.StreamCount {
				_ = conn.Close()
				return nil, errors.New("session stream metadata noto'g'ri")
			}
			for i := range ranges {
				if ranges[i].CipherSize != s.StreamPayloadSizes[i] {
					_ = conn.Close()
					return nil, errors.New("session stream payload manifest bilan mos emas")
				}
			}
			session = &s
			files, dirs := manifestCounts(manifest)
			fmt.Printf("[i] %d ta fayl, %d ta folder | Jami: %s\n", files, dirs, HumanBytes(manifest.TotalSize))
			fmt.Println("[🔒] AES-256-GCM manifest decrypt/authentication tasdiqlandi.")
		} else if !sameSessionIdentity(*joined.Session, *session) {
			_ = conn.Close()
			return nil, errors.New("resume session original transfer bilan mos emas")
		}

		staging, _, err = openReceiverStaging(outputDir, room, session.TransferID, manifest, plans, session.PayloadSize, session.StreamPayloadSizes)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		offsets := staging.streamOffsets()
		plainBase := int64(0)
		for i, r := range ranges {
			done, e := streamPlainDone(plans, r, offsets[i])
			if e != nil {
				_ = conn.Close()
				return nil, e
			}
			plainBase += done
		}
		if plainBase > 0 {
			fmt.Printf("[↻] Receiver resume: lokal state = %s (%5.2f%%)\n", HumanBytes(plainBase), percentage(plainBase, manifest.TotalSize))
		}

		readyMsg := protocol.Message{Type: protocol.TypeReceiverReady, Room: room}
		if session.StreamCount > 1 && !usingDirect {
			readyMsg.Offsets = offsets
		} else {
			readyMsg.Offset = offsets[0]
		}
		if err := protocol.WriteMessage(conn, readyMsg); err != nil {
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
		if ready.Type != protocol.TypePeerReady {
			_ = conn.Close()
			return nil, errors.New("server peer-ready noto'g'ri")
		}
		if session.StreamCount > 1 && !usingDirect {
			if len(ready.Offsets) != len(offsets) {
				_ = conn.Close()
				return nil, errors.New("server stream resume offset count noto'g'ri")
			}
			for i := range offsets {
				if ready.Offsets[i] != offsets[i] {
					_ = conn.Close()
					return nil, errors.New("server stream resume offsetni o'zgartirdi")
				}
			}
		} else if ready.Offset != offsets[0] {
			_ = conn.Close()
			return nil, errors.New("server noto'g'ri resume offset qaytardi")
		}

		progress := NewProgressWriter("Qabul qilish", manifest.TotalSize, plainBase)
		var recvErr error
		if session.StreamCount > 1 && !usingDirect {
			fmt.Printf("[⇶] Public relay: %d parallel TCP stream\n", session.StreamCount)
			recvErr = receivePublicStreams(cfg, room, session.AttachToken, dataAEAD, staging, plans, ranges, offsets, progress)
		} else {
			planIndex, e := streamPlanIndexForOffset(plans, ranges[0], offsets[0])
			if e != nil {
				_ = conn.Close()
				return nil, e
			}
			recvErr = receiveEncryptedChunks(conn, dataAEAD, staging, plans, planIndex, progress)
		}
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
	return receiveEncryptedChunksRange(conn, aead, staging, plans, 0, start, len(plans), progress)
}

func receiveEncryptedChunksRange(conn net.Conn, aead cipher.AEAD, staging *receiverStaging, plans []chunkPlan, streamID, start, end int, progress *ProgressWriter) error {
	if start < 0 || end < start || end > len(plans) {
		return errors.New("invalid encrypted chunk range")
	}
	maxCipherSize := aead.Overhead()
	for i := start; i < end; i++ {
		p := plans[i]
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

	streamOffset := staging.streamOffset(streamID)
	for i := start; i < end; i++ {
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
		streamOffset += p.CipherSize
		if err := staging.commitStreamOffset(streamID, streamOffset); err != nil {
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

func cancelPublicRoom(cfg ClientConfig, room, token string) {
	conn, err := cfg.dial()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCancel, Room: room, Token: token}) != nil {
		return
	}
	_, _ = protocol.ReadMessage(conn)
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
