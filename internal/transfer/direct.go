package transfer

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

var errDirectCanceled = errors.New("direct LAN transport canceled")

type directSender struct {
	ln      net.Listener
	room    string
	secret  []byte
	session protocol.SessionMeta
	aead    cipher.AEAD
	plans   []chunkPlan
	total   int64

	selected  chan struct{}
	done      chan error
	onceSel   sync.Once
	onceDone  sync.Once
	closeOnce sync.Once
}

func startDirectSender(secret []byte, session protocol.SessionMeta, aead cipher.AEAD, plans []chunkPlan, total int64) (*directSender, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	d := &directSender{
		ln: ln, secret: append([]byte(nil), secret...), session: cloneSession(session), aead: aead,
		plans: plans, total: total, selected: make(chan struct{}), done: make(chan error, 1),
	}
	return d, nil
}

func (d *directSender) Port() int {
	if d == nil || d.ln == nil {
		return 0
	}
	if a, ok := d.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

func (d *directSender) SetRoom(room string) { d.room = room }

func (d *directSender) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() { _ = d.ln.Close() })
}

func (d *directSender) finish(err error) {
	d.onceDone.Do(func() {
		d.Close()
		d.done <- err
		close(d.done)
	})
}

func (d *directSender) Serve() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				d.finish(errDirectCanceled)
			} else {
				d.finish(err)
			}
			return
		}
		configureAcceptedConn(conn)
		completed, err := d.handleConn(conn)
		_ = conn.Close()
		if completed {
			d.finish(nil)
			return
		}
		if err != nil {
			// Once LAN was selected, a broken TCP session is expected to be
			// resumed by a fresh authenticated direct connection.
			continue
		}
	}
}

func (d *directSender) handleConn(conn net.Conn) (bool, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	hello, err := protocol.ReadMessage(conn)
	if err != nil {
		return false, err
	}
	if hello.Type != protocol.TypeJoin && hello.Type != protocol.TypeResumeReceive {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "direct join expected"})
		return false, errors.New("direct join expected")
	}
	if d.room == "" || hello.Room != d.room || !verifyDirectProof(d.secret, d.room, hello.Proof) {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "direct authentication failed"})
		return false, errors.New("direct authentication failed")
	}

	d.onceSel.Do(func() { close(d.selected) })
	_ = conn.SetDeadline(time.Time{})
	session := cloneSession(d.session)
	// Resume aliases are only meaningful to the public relay and need not be
	// exposed by the direct endpoint.
	session.ResumeRooms = nil
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeJoined, Room: d.room, Session: &session}); err != nil {
		return false, err
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	ready, err := protocol.ReadMessage(conn)
	if err != nil {
		return false, err
	}
	if ready.Type != protocol.TypeReceiverReady {
		return false, errors.New("direct receiver_ready expected")
	}
	planIndex, err := chunkIndexForCipherOffset(d.plans, d.session.PayloadSize, ready.Offset)
	if err != nil {
		_ = protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeError, Text: "invalid direct resume offset"})
		return false, err
	}
	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypePeerReady, Room: d.room, Offset: ready.Offset}); err != nil {
		return false, err
	}

	plainBase := plainDoneAtPlanIndex(d.plans, planIndex, d.total)
	if ready.Offset > 0 {
		fmt.Printf("[↻] LAN resume: %s dan davom etadi (%5.2f%%)\n", HumanBytes(plainBase), percentage(plainBase, d.total))
	}
	progress := NewProgressWriter("Yuborish [LAN]", d.total, plainBase)
	err = sendEncryptedChunks(conn, d.aead, d.plans, planIndex, progress)
	progress.Finish()
	if err != nil {
		fmt.Printf("[!] LAN session uzildi: %s\n", networkErrorSummary(err))
		return false, err
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	verified, err := protocol.ReadMessage(conn)
	if err != nil {
		return false, err
	}
	if verified.Type == protocol.TypeError {
		return false, errors.New(verified.Text)
	}
	if verified.Type != protocol.TypeVerified {
		return false, errors.New("direct receiver verification missing")
	}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeComplete, Room: d.room}); err != nil {
		return false, err
	}
	return true, nil
}

func (c ClientConfig) dialAddr(addr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = c.ConnectTimeout
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	raw, err := d.Dial("tcp", addr)
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
	return raw, nil
}

func tryDirectReceiver(cfg ClientConfig, routes []string, room string, secret []byte, resume bool) (net.Conn, protocol.Message, string, error) {
	if len(routes) == 0 {
		return nil, protocol.Message{}, "", errors.New("no LAN candidates")
	}
	timeout := 700 * time.Millisecond
	if cfg.ConnectTimeout > 0 && cfg.ConnectTimeout < timeout {
		timeout = cfg.ConnectTimeout
	}
	msgType := protocol.TypeJoin
	if resume {
		msgType = protocol.TypeResumeReceive
	}
	proof := directProof(secret, room)
	var lastErr error
	for _, addr := range routes {
		conn, err := cfg.dialAddr(addr, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := protocol.WriteMessage(conn, protocol.Message{Type: msgType, Room: room, Proof: proof}); err != nil {
			lastErr = err
			_ = conn.Close()
			continue
		}
		joined, err := protocol.ReadMessage(conn)
		if err != nil {
			lastErr = err
			_ = conn.Close()
			continue
		}
		if joined.Type != protocol.TypeJoined || joined.Session == nil {
			if joined.Type == protocol.TypeError {
				lastErr = errors.New(joined.Text)
			} else {
				lastErr = errors.New("unexpected direct join response")
			}
			_ = conn.Close()
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, joined, addr, nil
	}
	if lastErr == nil {
		lastErr = errors.New("LAN endpoint topilmadi")
	}
	return nil, protocol.Message{}, "", lastErr
}
