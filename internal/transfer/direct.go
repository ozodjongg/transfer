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

	selected  chan string
	done      chan error
	onceSel   sync.Once
	onceDone  sync.Once
	closeOnce sync.Once
}

func startDirectSender(secret []byte, session protocol.SessionMeta, aead cipher.AEAD, plans []chunkPlan, total int64, listenLAN bool) (*directSender, error) {
	var ln net.Listener
	var err error
	if listenLAN {
		ln, err = net.Listen("tcp", ":0")
		if err != nil {
			return nil, err
		}
	}
	d := &directSender{
		ln: ln, secret: append([]byte(nil), secret...), session: cloneSession(session), aead: aead,
		plans: plans, total: total, selected: make(chan string, 1), done: make(chan error, 1),
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
	d.closeOnce.Do(func() {
		if d.ln != nil {
			_ = d.ln.Close()
		}
	})
}

func (d *directSender) finish(err error) {
	d.onceDone.Do(func() {
		d.Close()
		d.done <- err
		close(d.done)
	})
}

func (d *directSender) Serve() {
	if d == nil || d.ln == nil {
		return
	}
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
		completed, err := d.handleConn(conn, "LAN")
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

func (d *directSender) handleConn(conn net.Conn, transport string) (bool, error) {
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

	d.onceSel.Do(func() { d.selected <- transport })
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
	label := transport
	if label == "" {
		label = "DIRECT"
	}
	if ready.Offset > 0 {
		fmt.Printf("[↻] %s resume: %s dan davom etadi (%5.2f%%)\n", label, HumanBytes(plainBase), percentage(plainBase, d.total))
	}
	progress := NewProgressWriter("Yuborish ["+label+"]", d.total, plainBase)
	err = sendEncryptedChunks(conn, d.aead, d.plans, planIndex, progress)
	progress.Finish()
	if err != nil {
		fmt.Printf("[!] %s session uzildi: %s\n", label, networkErrorSummary(err))
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

func (d *directSender) ServeP2P(conn net.Conn) {
	if d == nil || conn == nil {
		return
	}
	completed, err := d.handleConn(conn, "P2P")
	_ = conn.Close()
	if completed {
		d.finish(nil)
		return
	}
	if err != nil {
		d.finish(err)
	}
}

func joinDirectConn(conn net.Conn, room string, secret []byte, resume bool) (protocol.Message, error) {
	if conn == nil {
		return protocol.Message{}, errors.New("direct connection nil")
	}
	msgType := protocol.TypeJoin
	if resume {
		msgType = protocol.TypeResumeReceive
	}
	proof := directProof(secret, room)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := protocol.WriteMessage(conn, protocol.Message{Type: msgType, Room: room, Proof: proof}); err != nil {
		return protocol.Message{}, err
	}
	joined, err := protocol.ReadMessage(conn)
	if err != nil {
		return protocol.Message{}, err
	}
	if joined.Type != protocol.TypeJoined || joined.Session == nil {
		if joined.Type == protocol.TypeError {
			return protocol.Message{}, errors.New(joined.Text)
		}
		return protocol.Message{}, errors.New("unexpected direct join response")
	}
	_ = conn.SetDeadline(time.Time{})
	return joined, nil
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
	var lastErr error
	for _, addr := range routes {
		conn, err := cfg.dialAddr(addr, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		joined, err := joinDirectConn(conn, room, secret, resume)
		if err != nil {
			lastErr = err
			_ = conn.Close()
			continue
		}
		return conn, joined, addr, nil
	}
	if lastErr == nil {
		lastErr = errors.New("LAN endpoint topilmadi")
	}
	return nil, protocol.Message{}, "", lastErr
}
