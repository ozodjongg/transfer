package transfer

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

const roomAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

type ServerConfig struct {
	Addr                   string
	RoomTTL                time.Duration
	TransferTimeout        time.Duration
	ResumeGrace            time.Duration
	MaxTransferSize        int64
	MaxEncryptedManifest   int
	MaxRooms               int
	MaxConnections         int
	MaxHandshakesPerMinute int
	TLSConfig              *tls.Config
	Logger                 *slog.Logger
}

type peerConn struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func newPeerConn(conn net.Conn) *peerConn {
	return &peerConn{conn: conn, done: make(chan struct{})}
}
func (p *peerConn) close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		_ = p.conn.Close()
		close(p.done)
	})
}

type room struct {
	code      string
	session   protocol.SessionMeta
	createdAt time.Time
	expiresAt time.Time

	sender         *peerConn
	receiver       *peerConn
	receiverOffset int64
	receiverReady  bool
	relaying       bool
	completed      bool

	done       chan struct{}
	finishOnce sync.Once
}

type rateWindow struct {
	start time.Time
	count int
}

type Server struct {
	cfg      ServerConfig
	mu       sync.Mutex
	rooms    map[string]*room
	rates    map[string]rateWindow
	sem      chan struct{}
	listener net.Listener
}

func NewServer(cfg ServerConfig) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.RoomTTL <= 0 {
		cfg.RoomTTL = 10 * time.Minute
	}
	if cfg.TransferTimeout <= 0 {
		cfg.TransferTimeout = 2 * time.Hour
	}
	if cfg.ResumeGrace <= 0 {
		cfg.ResumeGrace = 2 * time.Minute
	}
	if cfg.MaxTransferSize <= 0 {
		cfg.MaxTransferSize = 10 << 30
	}
	if cfg.MaxEncryptedManifest <= 0 {
		cfg.MaxEncryptedManifest = 2 * 1024 * 1024
	}
	if cfg.MaxRooms <= 0 {
		cfg.MaxRooms = 100
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 240
	}
	if cfg.MaxHandshakesPerMinute <= 0 {
		cfg.MaxHandshakesPerMinute = 600
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg: cfg, rooms: make(map[string]*room), rates: make(map[string]rateWindow),
		sem: make(chan struct{}, cfg.MaxConnections),
	}
}

func (s *Server) ListenAndServe() error {
	var ln net.Listener
	var err error
	if s.cfg.TLSConfig != nil {
		ln, err = tls.Listen("tcp", s.cfg.Addr, s.cfg.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", s.cfg.Addr)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	defer func() {
		_ = ln.Close()
		s.mu.Lock()
		if s.listener == ln {
			s.listener = nil
		}
		s.mu.Unlock()
	}()

	s.cfg.Logger.Info("server started",
		"addr", s.cfg.Addr, "tls", s.cfg.TLSConfig != nil,
		"protocol", protocol.Version, "e2e", true, "resume_grace", s.cfg.ResumeGrace)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.cfg.Logger.Warn("accept failed", "error", err)
			continue
		}
		configureAcceptedConn(conn)
		select {
		case s.sem <- struct{}{}:
			go func() {
				defer func() { <-s.sem }()
				s.handle(conn)
			}()
		default:
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "server busy"})
			_ = conn.Close()
		}
	}
}

func configureAcceptedConn(conn net.Conn) {
	raw := conn
	if tc, ok := conn.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(20 * time.Second)
		_ = tcp.SetReadBuffer(transferBufferSize)
		_ = tcp.SetWriteBuffer(transferBufferSize)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if !s.allowHandshake(conn.RemoteAddr()) {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "rate limit exceeded"})
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		s.cfg.Logger.Warn("bad handshake", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	switch msg.Type {
	case protocol.TypeCreate:
		s.handleCreate(conn, msg.Session)
	case protocol.TypeResumeSend:
		s.handleResumeSend(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), msg.Session)
	case protocol.TypeJoin:
		s.handleReceiver(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), false)
	case protocol.TypeResumeReceive:
		s.handleReceiver(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), true)
	default:
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "unknown command"})
	}
}

func (s *Server) handleCreate(conn net.Conn, session *protocol.SessionMeta) {
	if err := s.validateSession(session, true); err != nil {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: err.Error()})
		return
	}
	p := newPeerConn(conn)
	now := time.Now()
	r := &room{session: cloneSession(*session), createdAt: now, expiresAt: now.Add(s.cfg.RoomTTL), sender: p, done: make(chan struct{})}

	s.mu.Lock()
	if len(s.rooms) >= s.cfg.MaxRooms {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "server room capacity reached"})
		return
	}
	for {
		code, err := secureRoomCode(10)
		if err != nil {
			s.mu.Unlock()
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room generation failed"})
			return
		}
		if _, exists := s.rooms[code]; !exists {
			r.code = code
			s.rooms[code] = r
			break
		}
	}
	s.mu.Unlock()

	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreated, Room: r.code}); err != nil {
		s.finishRoom(r, "sender disconnected before room acknowledgement")
		return
	}
	s.cfg.Logger.Info("room created",
		"room", r.code, "remote", conn.RemoteAddr().String(),
		"plain_size", session.PlainSize, "payload_size", session.PayloadSize,
		"encrypted_manifest_bytes", len(session.EncryptedManifest), "transfer_id", session.TransferID[:12])
	go s.roomJanitor(r)
	<-p.done
}

func (s *Server) handleResumeSend(conn net.Conn, code string, session *protocol.SessionMeta) {
	if code == "" {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room code required"})
		return
	}
	if err := s.validateSession(session, false); err != nil {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: err.Error()})
		return
	}
	p := newPeerConn(conn)
	var old *peerConn
	s.mu.Lock()
	r, ok := s.rooms[code]
	if !ok {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room not found or resume window expired"})
		return
	}
	if r.completed {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeComplete, Room: code})
		return
	}
	if !sameSessionIdentity(r.session, *session) {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "resume session original room bilan mos emas"})
		return
	}
	old = r.sender
	r.sender = p
	r.expiresAt = time.Now().Add(s.cfg.ResumeGrace)
	s.mu.Unlock()

	if old != nil && old != p {
		old.close()
	}
	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeJoined, Room: code}); err != nil {
		p.close()
		return
	}
	s.cfg.Logger.Info("sender resumed", "room", code, "remote", conn.RemoteAddr().String())
	s.maybeStartRelay(r)
	<-p.done
}

func (s *Server) handleReceiver(conn net.Conn, code string, resume bool) {
	if code == "" {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room code required"})
		return
	}
	p := newPeerConn(conn)
	var old *peerConn
	s.mu.Lock()
	r, ok := s.rooms[code]
	if !ok {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room not found or resume window expired"})
		return
	}
	if r.completed {
		s.mu.Unlock()
		if resume {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeComplete, Room: code})
		} else {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room already completed"})
		}
		return
	}
	if !resume && r.receiver != nil {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room already has a receiver"})
		return
	}
	old = r.receiver
	r.receiver = p
	r.receiverReady = false
	r.expiresAt = time.Now().Add(s.cfg.ResumeGrace)
	session := cloneSession(r.session)
	s.mu.Unlock()

	if old != nil && old != p {
		old.close()
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeJoined, Room: code, Session: &session}); err != nil {
		p.close()
		return
	}
	ready, err := protocol.ReadMessage(conn)
	if err != nil {
		p.close()
		return
	}
	if ready.Type != protocol.TypeReceiverReady {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "receiver_ready expected"})
		p.close()
		return
	}
	if ready.Offset < 0 || ready.Offset > session.PayloadSize {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid resume offset"})
		p.close()
		return
	}

	s.mu.Lock()
	if current, exists := s.rooms[code]; !exists || current != r || r.receiver != p || r.completed {
		s.mu.Unlock()
		p.close()
		return
	}
	r.receiverOffset = ready.Offset
	r.receiverReady = true
	r.expiresAt = time.Now().Add(s.cfg.TransferTimeout)
	s.mu.Unlock()

	_ = conn.SetDeadline(time.Time{})
	if resume {
		s.cfg.Logger.Info("receiver resumed", "room", code, "remote", conn.RemoteAddr().String(), "cipher_offset", ready.Offset)
	} else {
		s.cfg.Logger.Info("receiver joined", "room", code, "remote", conn.RemoteAddr().String(), "cipher_offset", ready.Offset)
	}
	s.maybeStartRelay(r)
	<-p.done
}

func (s *Server) maybeStartRelay(r *room) {
	s.mu.Lock()
	if r.completed || r.relaying || r.sender == nil || r.receiver == nil || !r.receiverReady {
		s.mu.Unlock()
		return
	}
	sp, rp := r.sender, r.receiver
	offset := r.receiverOffset
	session := cloneSession(r.session)
	r.relaying = true
	r.expiresAt = time.Now().Add(s.cfg.TransferTimeout)
	s.mu.Unlock()
	go s.relaySession(r, sp, rp, offset, session)
}

func (s *Server) relaySession(r *room, sp, rp *peerConn, offset int64, session protocol.SessionMeta) {
	started := time.Now()
	remaining := session.PayloadSize - offset
	if remaining < 0 {
		s.failRoomTerminal(r, "invalid relay offset")
		return
	}
	_ = sp.conn.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))
	_ = rp.conn.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))

	ready := protocol.Message{Type: protocol.TypePeerReady, Room: r.code, Offset: offset}
	if err := protocol.WriteMessage(sp.conn, ready); err != nil {
		s.recoverRelay(r, sp, rp, offset, 0, started, fmt.Errorf("notify sender: %w", err))
		return
	}
	if err := protocol.WriteMessage(rp.conn, ready); err != nil {
		s.recoverRelay(r, sp, rp, offset, 0, started, fmt.Errorf("notify receiver: %w", err))
		return
	}

	s.cfg.Logger.Info("encrypted transfer started", "room", r.code, "cipher_offset", offset, "cipher_remaining", remaining)
	buf, put := getTransferBuffer()
	written, err := io.CopyBuffer(rp.conn, io.LimitReader(sp.conn, remaining), *buf)
	put()
	if err != nil {
		s.recoverRelay(r, sp, rp, offset, written, started, fmt.Errorf("relay interrupted: %w", err))
		return
	}
	if written != remaining {
		s.recoverRelay(r, sp, rp, offset, written, started, fmt.Errorf("short relay: %d/%d bytes: %w", written, remaining, io.ErrUnexpectedEOF))
		return
	}

	verified, err := protocol.ReadMessage(rp.conn)
	if err != nil {
		s.recoverRelay(r, sp, rp, offset, written, started, fmt.Errorf("receiver verification acknowledgement: %w", err))
		return
	}
	if verified.Type == protocol.TypeError {
		s.failRoomTerminal(r, "receiver verification failed: "+verified.Text)
		return
	}
	if verified.Type != protocol.TypeVerified {
		s.failRoomTerminal(r, "receiver did not verify transfer")
		return
	}
	s.markComplete(r, sp, rp, started)
}

func (s *Server) recoverRelay(r *room, sp, rp *peerConn, offset, written int64, started time.Time, err error) {
	sp.close()
	rp.close()
	s.mu.Lock()
	if r.completed {
		s.mu.Unlock()
		return
	}
	if r.sender == sp {
		r.sender = nil
	}
	if r.receiver == rp {
		r.receiver = nil
		r.receiverReady = false
	}
	r.relaying = false
	r.expiresAt = time.Now().Add(s.cfg.ResumeGrace)
	s.mu.Unlock()

	elapsed := time.Since(started)
	avg := 0.0
	if elapsed > 0 {
		avg = float64(written) / elapsed.Seconds()
	}
	s.cfg.Logger.Warn("encrypted transfer interrupted; resume available",
		"room", r.code, "cipher_bytes_session", written,
		"cipher_server_observed", offset+written, "payload_size", r.session.PayloadSize,
		"elapsed", elapsed.Round(time.Millisecond), "avg_mib_s", avg/(1024*1024),
		"resume_grace", s.cfg.ResumeGrace, "error", err)
	s.maybeStartRelay(r)
}

func (s *Server) markComplete(r *room, sp, rp *peerConn, started time.Time) {
	s.mu.Lock()
	if r.completed {
		s.mu.Unlock()
		return
	}
	r.completed = true
	r.relaying = false
	r.expiresAt = time.Now().Add(s.cfg.ResumeGrace)
	if r.sender == sp {
		r.sender = nil
	}
	if r.receiver == rp {
		r.receiver = nil
		r.receiverReady = false
	}
	s.mu.Unlock()

	_ = protocol.WriteMessage(rp.conn, protocol.Message{Type: protocol.TypeComplete, Room: r.code})
	_ = protocol.WriteMessage(sp.conn, protocol.Message{Type: protocol.TypeComplete, Room: r.code})
	sp.close()
	rp.close()
	s.cfg.Logger.Info("encrypted transfer complete",
		"room", r.code, "plain_size", r.session.PlainSize, "payload_size", r.session.PayloadSize,
		"session_elapsed", time.Since(started).Round(time.Millisecond), "completion_cache", s.cfg.ResumeGrace)
}

func (s *Server) failRoomTerminal(r *room, reason string) {
	s.mu.Lock()
	sp, rp := r.sender, r.receiver
	s.mu.Unlock()
	if sp != nil {
		_ = protocol.WriteMessage(sp.conn, protocol.Message{Type: protocol.TypeError, Room: r.code, Text: reason})
	}
	if rp != nil {
		_ = protocol.WriteMessage(rp.conn, protocol.Message{Type: protocol.TypeError, Room: r.code, Text: reason})
	}
	s.cfg.Logger.Warn("transfer terminated", "room", r.code, "reason", reason)
	s.finishRoom(r, reason)
}

func (s *Server) roomJanitor(r *room) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			current, ok := s.rooms[r.code]
			expiresAt, completed := r.expiresAt, r.completed
			s.mu.Unlock()
			if !ok || current != r {
				return
			}
			if time.Now().After(expiresAt) {
				reason := "room expired"
				if completed {
					reason = "completed room cache expired"
				}
				s.finishRoom(r, reason)
				return
			}
		}
	}
}

func (s *Server) finishRoom(r *room, reason string) {
	r.finishOnce.Do(func() {
		s.mu.Lock()
		if current, ok := s.rooms[r.code]; ok && current == r {
			delete(s.rooms, r.code)
		}
		sp, rp := r.sender, r.receiver
		r.sender, r.receiver = nil, nil
		s.mu.Unlock()
		if sp != nil {
			sp.close()
		}
		if rp != nil {
			rp.close()
		}
		close(r.done)
		s.cfg.Logger.Info("room closed", "room", r.code, "reason", reason)
	})
}

func (s *Server) validateSession(session *protocol.SessionMeta, requireManifest bool) error {
	if session == nil {
		return errors.New("session metadata required")
	}
	if len(session.TransferID) != 64 {
		return errors.New("invalid transfer_id")
	}
	if session.PlainSize < 0 || session.PlainSize > s.cfg.MaxTransferSize {
		return fmt.Errorf("transfer size %d exceeds server limit", session.PlainSize)
	}
	if session.PayloadSize < session.PlainSize || session.PayloadSize > s.cfg.MaxTransferSize+(1<<30) {
		return errors.New("invalid encrypted payload size")
	}
	if requireManifest {
		if len(session.EncryptedManifest) == 0 || len(session.EncryptedManifest) > s.cfg.MaxEncryptedManifest {
			return errors.New("encrypted manifest missing or too large")
		}
		if transferID(session.EncryptedManifest) != session.TransferID {
			return errors.New("transfer_id does not match encrypted manifest")
		}
	}
	return nil
}

func sameSessionIdentity(a, b protocol.SessionMeta) bool {
	return a.TransferID == b.TransferID && a.PlainSize == b.PlainSize && a.PayloadSize == b.PayloadSize
}

func cloneSession(s protocol.SessionMeta) protocol.SessionMeta {
	out := s
	if s.EncryptedManifest != nil {
		out.EncryptedManifest = append([]byte(nil), s.EncryptedManifest...)
	}
	return out
}

func (s *Server) allowHandshake(addr net.Addr) bool {
	host := addr.String()
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		host = h
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rates) > 4096 {
		for ip, w := range s.rates {
			if now.Sub(w.start) > 5*time.Minute {
				delete(s.rates, ip)
			}
		}
	}
	w := s.rates[host]
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		s.rates[host] = rateWindow{start: now, count: 1}
		return true
	}
	if w.count >= s.cfg.MaxHandshakesPerMinute {
		return false
	}
	w.count++
	s.rates[host] = w
	return true
}

func (s *Server) Shutdown() error {
	s.mu.Lock()
	ln := s.listener
	rooms := make([]*room, 0, len(s.rooms))
	for _, r := range s.rooms {
		rooms = append(rooms, r)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, r := range rooms {
		s.finishRoom(r, "server shutdown")
	}
	return nil
}

func secureRoomCode(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("invalid room code length")
	}
	buf, raw := make([]byte, n), make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i, b := range raw {
		buf[i] = roomAlphabet[int(b)%len(roomAlphabet)]
	}
	return string(buf), nil
}
