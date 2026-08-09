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
	aliases   []string
	session   protocol.SessionMeta
	createdAt time.Time
	expiresAt time.Time

	sender          *peerConn
	receiver        *peerConn
	receiverOffset  int64
	receiverOffsets []int64
	receiverReady   bool
	relaying        bool
	completed       bool
	verified        bool

	senderData   map[int]*peerConn
	receiverData map[int]*peerConn
	streamDone   []bool

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
	aliases  map[string]*room
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
		cfg: cfg, rooms: make(map[string]*room), aliases: make(map[string]*room), rates: make(map[string]rateWindow),
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
	case protocol.TypeDataSend:
		s.handleData(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), msg.Stream, msg.Token, true)
	case protocol.TypeDataReceive:
		s.handleData(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), msg.Stream, msg.Token, false)
	case protocol.TypeCancel:
		s.handleCancel(conn, strings.ToUpper(strings.TrimSpace(msg.Room)), msg.Token)
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
	r := &room{session: cloneSession(*session), aliases: append([]string(nil), session.ResumeRooms...), createdAt: now, expiresAt: now.Add(s.cfg.RoomTTL), sender: p, done: make(chan struct{}), senderData: make(map[int]*peerConn), receiverData: make(map[int]*peerConn), streamDone: make([]bool, session.StreamCount)}

	s.mu.Lock()
	if len(s.rooms) >= s.cfg.MaxRooms {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "server room capacity reached"})
		return
	}
	for _, alias := range r.aliases {
		if _, exists := s.rooms[alias]; exists {
			s.mu.Unlock()
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "resume alias collision; retry transfer"})
			return
		}
		if _, exists := s.aliases[alias]; exists {
			s.mu.Unlock()
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "resume alias collision; retry transfer"})
			return
		}
	}
	for {
		code, err := secureRoomCode(10)
		if err != nil {
			s.mu.Unlock()
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room generation failed"})
			return
		}
		if _, exists := s.rooms[code]; !exists {
			if _, aliasExists := s.aliases[code]; aliasExists {
				continue
			}
			r.code = code
			s.rooms[code] = r
			for _, alias := range r.aliases {
				s.aliases[alias] = r
			}
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
	r, ok := s.lookupRoomLocked(code)
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
	r, ok := s.lookupRoomLocked(code)
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
	// Receiver derives routing credentials from the E2E secret; do not expose
	// resume aliases or the data attach token in relay responses.
	session.ResumeRooms = nil
	session.AttachToken = ""
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
	var offsets []int64
	if session.StreamCount > 1 {
		if len(ready.Offsets) != session.StreamCount {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid stream resume offsets"})
			p.close()
			return
		}
		offsets = append([]int64(nil), ready.Offsets...)
		for i, off := range offsets {
			if off < 0 || off > session.StreamPayloadSizes[i] {
				_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid stream resume offset"})
				p.close()
				return
			}
		}
	} else {
		if ready.Offset < 0 || ready.Offset > session.PayloadSize {
			_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid resume offset"})
			p.close()
			return
		}
		offsets = []int64{ready.Offset}
	}

	s.mu.Lock()
	if current, exists := s.lookupRoomLocked(code); !exists || current != r || r.receiver != p || r.completed {
		s.mu.Unlock()
		p.close()
		return
	}
	r.receiverOffset = ready.Offset
	r.receiverOffsets = offsets
	r.receiverReady = true
	r.verified = false
	if len(r.streamDone) != session.StreamCount {
		r.streamDone = make([]bool, session.StreamCount)
	}
	for i := range r.streamDone {
		r.streamDone[i] = i < len(offsets) && offsets[i] == session.StreamPayloadSizes[i]
	}
	r.expiresAt = time.Now().Add(s.cfg.TransferTimeout)
	s.mu.Unlock()

	_ = conn.SetDeadline(time.Time{})
	if resume {
		s.cfg.Logger.Info("receiver resumed", "room", r.code, "via", code, "remote", conn.RemoteAddr().String(), "cipher_offset", ready.Offset, "stream_offsets", offsets)
	} else {
		s.cfg.Logger.Info("receiver joined", "room", r.code, "via", code, "remote", conn.RemoteAddr().String(), "cipher_offset", ready.Offset, "stream_offsets", offsets)
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
	offsets := append([]int64(nil), r.receiverOffsets...)
	session := cloneSession(r.session)
	r.relaying = true
	r.expiresAt = time.Now().Add(s.cfg.TransferTimeout)
	s.mu.Unlock()

	if session.StreamCount > 1 {
		ready := protocol.Message{Type: protocol.TypePeerReady, Room: r.code, Offsets: offsets}
		if err := protocol.WriteMessage(sp.conn, ready); err != nil {
			s.recoverMultiRelay(r, fmt.Errorf("notify sender: %w", err))
			return
		}
		if err := protocol.WriteMessage(rp.conn, ready); err != nil {
			s.recoverMultiRelay(r, fmt.Errorf("notify receiver: %w", err))
			return
		}
		s.cfg.Logger.Info("parallel encrypted transfer ready", "room", r.code, "streams", session.StreamCount, "stream_offsets", offsets)
		go s.waitMultiVerification(r, rp)
		for i := 0; i < session.StreamCount; i++ {
			s.maybeStartDataRelay(r, i)
		}
		return
	}
	go s.relaySession(r, sp, rp, offset, session)
}

func (s *Server) handleCancel(conn net.Conn, code, token string) {
	s.mu.Lock()
	r, ok := s.lookupRoomLocked(code)
	if !ok {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeComplete, Room: code})
		return
	}
	if token == "" || token != r.session.AttachToken {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid cancel token"})
		return
	}
	s.mu.Unlock()
	_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeComplete, Room: r.code})
	s.finishRoom(r, "sender selected LAN direct transport")
}

func (s *Server) handleData(conn net.Conn, code string, stream int, token string, sender bool) {
	p := newPeerConn(conn)
	s.mu.Lock()
	r, ok := s.lookupRoomLocked(code)
	if !ok || r.completed {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room not found or completed"})
		return
	}
	if r.session.StreamCount <= 1 || stream < 0 || stream >= r.session.StreamCount {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid data stream"})
		return
	}
	if token == "" || token != r.session.AttachToken {
		s.mu.Unlock()
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid data attach token"})
		return
	}
	var old *peerConn
	if sender {
		old = r.senderData[stream]
		r.senderData[stream] = p
	} else {
		old = r.receiverData[stream]
		r.receiverData[stream] = p
	}
	r.expiresAt = time.Now().Add(s.cfg.TransferTimeout)
	s.mu.Unlock()
	if old != nil && old != p {
		old.close()
	}
	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeJoined, Room: r.code, Stream: stream}); err != nil {
		p.close()
		return
	}
	s.maybeStartDataRelay(r, stream)
	<-p.done
}

func (s *Server) maybeStartDataRelay(r *room, stream int) {
	s.mu.Lock()
	if r.completed || !r.relaying || r.session.StreamCount <= 1 || stream < 0 || stream >= r.session.StreamCount || r.streamDone[stream] {
		s.mu.Unlock()
		return
	}
	sp := r.senderData[stream]
	rp := r.receiverData[stream]
	if sp == nil || rp == nil {
		s.mu.Unlock()
		return
	}
	offset := int64(0)
	if stream < len(r.receiverOffsets) {
		offset = r.receiverOffsets[stream]
	}
	remaining := r.session.StreamPayloadSizes[stream] - offset
	if remaining < 0 {
		s.mu.Unlock()
		s.recoverMultiRelay(r, errors.New("negative data stream remaining size"))
		return
	}
	// Remove from maps while active so duplicate attaches replace only future
	// sessions, not a currently relaying stream.
	delete(r.senderData, stream)
	delete(r.receiverData, stream)
	s.mu.Unlock()
	go s.relayDataStream(r, stream, sp, rp, offset, remaining)
}

func (s *Server) relayDataStream(r *room, stream int, sp, rp *peerConn, offset, remaining int64) {
	started := time.Now()
	_ = sp.conn.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))
	_ = rp.conn.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))
	buf, put := getTransferBuffer()
	written, err := io.CopyBuffer(rp.conn, io.LimitReader(sp.conn, remaining), *buf)
	put()
	if err != nil || written != remaining {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		sp.close()
		rp.close()
		s.recoverMultiRelay(r, fmt.Errorf("stream %d interrupted after %d/%d: %w", stream, written, remaining, err))
		return
	}
	sp.close()
	rp.close()
	s.mu.Lock()
	if !r.completed && r.relaying && stream < len(r.streamDone) {
		r.streamDone[stream] = true
	}
	s.mu.Unlock()
	s.cfg.Logger.Info("parallel data stream complete", "room", r.code, "stream", stream, "bytes", written, "elapsed", time.Since(started).Round(time.Millisecond))
	s.maybeCompleteMulti(r)
}

func (s *Server) waitMultiVerification(r *room, rp *peerConn) {
	msg, err := protocol.ReadMessage(rp.conn)
	if err != nil {
		s.recoverMultiRelay(r, fmt.Errorf("parallel receiver verification: %w", err))
		return
	}
	if msg.Type == protocol.TypeError {
		s.failRoomTerminal(r, "receiver verification failed: "+msg.Text)
		return
	}
	if msg.Type != protocol.TypeVerified {
		s.recoverMultiRelay(r, errors.New("parallel receiver did not verify transfer"))
		return
	}
	s.mu.Lock()
	if !r.completed && r.receiver == rp {
		r.verified = true
	}
	s.mu.Unlock()
	s.maybeCompleteMulti(r)
}

func (s *Server) maybeCompleteMulti(r *room) {
	s.mu.Lock()
	if r.completed || !r.relaying || !r.verified {
		s.mu.Unlock()
		return
	}
	for _, done := range r.streamDone {
		if !done {
			s.mu.Unlock()
			return
		}
	}
	sp, rp := r.sender, r.receiver
	s.mu.Unlock()
	if sp == nil || rp == nil {
		return
	}
	s.markComplete(r, sp, rp, time.Now())
}

func (s *Server) recoverMultiRelay(r *room, err error) {
	s.mu.Lock()
	if r.completed || !r.relaying {
		s.mu.Unlock()
		return
	}
	r.relaying = false
	r.receiverReady = false
	r.verified = false
	sp, rp := r.sender, r.receiver
	r.sender, r.receiver = nil, nil
	data := make([]*peerConn, 0, len(r.senderData)+len(r.receiverData))
	for _, p := range r.senderData {
		data = append(data, p)
	}
	for _, p := range r.receiverData {
		data = append(data, p)
	}
	r.senderData = make(map[int]*peerConn)
	r.receiverData = make(map[int]*peerConn)
	for i := range r.streamDone {
		r.streamDone[i] = false
	}
	r.expiresAt = time.Now().Add(s.cfg.ResumeGrace)
	s.mu.Unlock()
	if sp != nil {
		sp.close()
	}
	if rp != nil {
		rp.close()
	}
	for _, p := range data {
		p.close()
	}
	s.cfg.Logger.Warn("parallel transfer interrupted; resume available", "room", r.code, "resume_grace", s.cfg.ResumeGrace, "error", err)
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
		for _, alias := range r.aliases {
			if current, ok := s.aliases[alias]; ok && current == r {
				delete(s.aliases, alias)
			}
		}
		sp, rp := r.sender, r.receiver
		data := make([]*peerConn, 0, len(r.senderData)+len(r.receiverData))
		for _, p := range r.senderData {
			data = append(data, p)
		}
		for _, p := range r.receiverData {
			data = append(data, p)
		}
		r.sender, r.receiver = nil, nil
		r.senderData = make(map[int]*peerConn)
		r.receiverData = make(map[int]*peerConn)
		s.mu.Unlock()
		if sp != nil {
			sp.close()
		}
		if rp != nil {
			rp.close()
		}
		for _, p := range data {
			p.close()
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
	if session.StreamCount < 1 || session.StreamCount > maxParallelStreams {
		return errors.New("invalid stream_count")
	}
	if len(session.StreamPayloadSizes) != session.StreamCount {
		return errors.New("stream payload size count mismatch")
	}
	var streamTotal int64
	for _, n := range session.StreamPayloadSizes {
		if n < 0 {
			return errors.New("negative stream payload size")
		}
		streamTotal += n
	}
	if streamTotal != session.PayloadSize {
		return errors.New("stream payload sizes do not sum to payload_size")
	}
	if len(session.AttachToken) < 24 || len(session.AttachToken) > 128 {
		return errors.New("invalid attach token")
	}
	if len(session.ResumeRooms) > 16 {
		return errors.New("too many resume aliases")
	}
	seenAliases := make(map[string]struct{}, len(session.ResumeRooms))
	for _, alias := range session.ResumeRooms {
		if !validResumeAlias(alias) {
			return errors.New("invalid resume alias")
		}
		if _, exists := seenAliases[alias]; exists {
			return errors.New("duplicate resume alias")
		}
		seenAliases[alias] = struct{}{}
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
	if a.TransferID != b.TransferID || a.PlainSize != b.PlainSize || a.PayloadSize != b.PayloadSize || a.StreamCount != b.StreamCount || a.AttachToken != b.AttachToken {
		return false
	}
	if len(a.StreamPayloadSizes) != len(b.StreamPayloadSizes) {
		return false
	}
	for i := range a.StreamPayloadSizes {
		if a.StreamPayloadSizes[i] != b.StreamPayloadSizes[i] {
			return false
		}
	}
	return true
}

func cloneSession(s protocol.SessionMeta) protocol.SessionMeta {
	out := s
	if s.EncryptedManifest != nil {
		out.EncryptedManifest = append([]byte(nil), s.EncryptedManifest...)
	}
	if s.ResumeRooms != nil {
		out.ResumeRooms = append([]string(nil), s.ResumeRooms...)
	}
	if s.StreamPayloadSizes != nil {
		out.StreamPayloadSizes = append([]int64(nil), s.StreamPayloadSizes...)
	}
	return out
}

func validResumeAlias(alias string) bool {
	if len(alias) != 16 {
		return false
	}
	for _, r := range alias {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

func (s *Server) lookupRoomLocked(code string) (*room, bool) {
	if r, ok := s.rooms[code]; ok {
		return r, true
	}
	r, ok := s.aliases[code]
	return r, ok
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
