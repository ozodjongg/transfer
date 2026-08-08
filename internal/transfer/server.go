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
	MaxFileSize            int64
	MaxConnections         int
	MaxHandshakesPerMinute int
	TLSConfig              *tls.Config
	Logger                 *slog.Logger
}

type room struct {
	code       string
	sender     net.Conn
	receiver   net.Conn
	createdAt  time.Time
	ready      chan struct{}
	done       chan struct{}
	readyOnce  sync.Once
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
	if cfg.RoomTTL <= 0 {
		cfg.RoomTTL = 10 * time.Minute
	}
	if cfg.TransferTimeout <= 0 {
		cfg.TransferTimeout = 2 * time.Hour
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 10 << 30
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 512
	}
	if cfg.MaxHandshakesPerMinute <= 0 {
		cfg.MaxHandshakesPerMinute = 120
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:   cfg,
		rooms: make(map[string]*room),
		rates: make(map[string]rateWindow),
		sem:   make(chan struct{}, cfg.MaxConnections),
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

	s.cfg.Logger.Info("server started", "addr", s.cfg.Addr, "tls", s.cfg.TLSConfig != nil)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.cfg.Logger.Warn("accept failed", "error", err)
			continue
		}

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
		s.handleCreate(conn)
	case protocol.TypeJoin:
		s.handleJoin(conn, strings.ToUpper(strings.TrimSpace(msg.Room)))
	default:
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "unknown command"})
	}
}

func (s *Server) handleCreate(conn net.Conn) {
	r := &room{sender: conn, createdAt: time.Now(), ready: make(chan struct{}), done: make(chan struct{})}

	s.mu.Lock()
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

	defer s.finishRoom(r)
	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeCreated, Room: r.code}); err != nil {
		return
	}
	s.cfg.Logger.Info("room created", "room", r.code, "remote", conn.RemoteAddr().String())

	timer := time.NewTimer(s.cfg.RoomTTL)
	defer timer.Stop()
	select {
	case <-r.ready:
		if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypePeerReady, Room: r.code}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))
		<-r.done
	case <-timer.C:
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "room expired"})
		s.cfg.Logger.Info("room expired", "room", r.code)
	}
}

func (s *Server) handleJoin(receiver net.Conn, code string) {
	if code == "" {
		_ = protocol.WriteMessage(receiver, protocol.Message{Type: protocol.TypeError, Text: "room code required"})
		return
	}

	s.mu.Lock()
	r, ok := s.rooms[code]
	if !ok || r.receiver != nil || time.Since(r.createdAt) > s.cfg.RoomTTL {
		s.mu.Unlock()
		_ = protocol.WriteMessage(receiver, protocol.Message{Type: protocol.TypeError, Text: "room not found, expired, or already joined"})
		return
	}
	r.receiver = receiver
	s.mu.Unlock()

	if err := protocol.WriteMessage(receiver, protocol.Message{Type: protocol.TypeJoined, Room: code}); err != nil {
		s.finishRoom(r)
		return
	}
	_ = receiver.SetDeadline(time.Now().Add(s.cfg.TransferTimeout))
	r.readyOnce.Do(func() { close(r.ready) })
	s.cfg.Logger.Info("receiver joined", "room", code, "remote", receiver.RemoteAddr().String())

	if err := s.relay(r); err != nil {
		s.cfg.Logger.Warn("transfer failed", "room", code, "error", err)
		_ = protocol.WriteMessage(receiver, protocol.Message{Type: protocol.TypeError, Text: err.Error()})
		_ = protocol.WriteMessage(r.sender, protocol.Message{Type: protocol.TypeError, Text: err.Error()})
	} else {
		_ = protocol.WriteMessage(receiver, protocol.Message{Type: protocol.TypeComplete, Room: code})
		_ = protocol.WriteMessage(r.sender, protocol.Message{Type: protocol.TypeComplete, Room: code})
		s.cfg.Logger.Info("transfer complete", "room", code)
	}
	s.finishRoom(r)
}

func (s *Server) relay(r *room) error {
	metaMsg, err := protocol.ReadMessage(r.sender)
	if err != nil {
		return fmt.Errorf("read file metadata: %w", err)
	}
	if metaMsg.Type != protocol.TypeFileMeta || metaMsg.File == nil {
		return errors.New("invalid file metadata")
	}
	meta := metaMsg.File
	if meta.Size < 0 || meta.Size > s.cfg.MaxFileSize {
		return fmt.Errorf("file size %d exceeds server limit", meta.Size)
	}
	if len(meta.Name) == 0 || len(meta.Name) > 255 {
		return errors.New("invalid file name")
	}
	if len(meta.SHA256) != 64 {
		return errors.New("invalid sha256 metadata")
	}
	if err := protocol.WriteMessage(r.receiver, metaMsg); err != nil {
		return fmt.Errorf("send file metadata: %w", err)
	}

	written, err := io.CopyN(r.receiver, r.sender, meta.Size)
	if err != nil {
		return fmt.Errorf("relay interrupted after %d/%d bytes: %w", written, meta.Size, err)
	}
	if written != meta.Size {
		return fmt.Errorf("short relay: %d/%d bytes", written, meta.Size)
	}
	return nil
}

func (s *Server) finishRoom(r *room) {
	r.finishOnce.Do(func() {
		s.mu.Lock()
		if current, ok := s.rooms[r.code]; ok && current == r {
			delete(s.rooms, r.code)
		}
		s.mu.Unlock()
		close(r.done)
		s.cfg.Logger.Info("room closed", "room", r.code)
	})
}

func (s *Server) allowHandshake(addr net.Addr) bool {
	host := addr.String()
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		host = h
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
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
		if r.sender != nil {
			_ = r.sender.Close()
		}
		if r.receiver != nil {
			_ = r.receiver.Close()
		}
		s.finishRoom(r)
	}
	return nil
}

func secureRoomCode(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("invalid room code length")
	}
	buf := make([]byte, n)
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i, b := range raw {
		buf[i] = roomAlphabet[int(b)%len(roomAlphabet)]
	}
	return string(buf), nil
}
