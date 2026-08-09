package transfer

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.com/pro-transfer/internal/protocol"
)

func TestTransferResumesAfterForcedSenderDisconnect(t *testing.T) {
	serverAddr := freeTCPAddr(t)
	server := NewServer(ServerConfig{
		Addr:                   serverAddr,
		RoomTTL:                10 * time.Second,
		TransferTimeout:        30 * time.Second,
		ResumeGrace:            10 * time.Second,
		MaxFileSize:            64 << 20,
		MaxConnections:         32,
		MaxHandshakesPerMinute: 1000,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	defer server.Shutdown()
	waitForTCP(t, serverAddr)

	proxy := newDropOnceProxy(t, serverAddr, 1<<20)
	defer proxy.Close()

	sendDir := t.TempDir()
	recvDir := t.TempDir()
	source := filepath.Join(sendDir, "resume.bin")
	payload := bytes.Repeat([]byte("pro-transfer-v4-resume-test\n"), 320000) // ~8 MiB
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	roomCh := make(chan string, 1)
	sendCfg := ClientConfig{
		Addr:           proxy.Addr(),
		ConnectTimeout: 2 * time.Second,
		IOTimeout:      30 * time.Second,
		OnRoomCreated: func(room string) {
			select {
			case roomCh <- room:
			default:
			}
		},
	}
	recvCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second}

	type result struct {
		path string
		err  error
	}
	sendResult := make(chan result, 1)
	go func() {
		_, err := SendFile(sendCfg, source)
		sendResult <- result{err: err}
	}()

	var room string
	select {
	case room = <-roomCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not create a room")
	}

	recvResult := make(chan result, 1)
	go func() {
		path, err := ReceiveFile(recvCfg, room, recvDir)
		recvResult <- result{path: path, err: err}
	}()

	select {
	case r := <-sendResult:
		if r.err != nil {
			t.Fatalf("sender failed: %v", r.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("sender timed out")
	}

	var received string
	select {
	case r := <-recvResult:
		if r.err != nil {
			t.Fatalf("receiver failed: %v", r.err)
		}
		received = r.path
	case <-time.After(15 * time.Second):
		t.Fatal("receiver timed out")
	}

	got, err := os.ReadFile(received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("received file differs from source after resume")
	}
	if !proxy.dropped.Load() {
		t.Fatal("test proxy did not force the sender disconnect")
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server stopped unexpectedly: %v", err)
		}
	default:
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server %s did not become ready", addr)
}

type dropOnceProxy struct {
	ln        net.Listener
	target    string
	dropAfter int64
	dropped   atomic.Bool
	closed    chan struct{}
	wg        sync.WaitGroup
}

func newDropOnceProxy(t *testing.T, target string, dropAfter int64) *dropOnceProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &dropOnceProxy{ln: ln, target: target, dropAfter: dropAfter, closed: make(chan struct{})}
	p.wg.Add(1)
	go p.acceptLoop()
	return p
}

func (p *dropOnceProxy) Addr() string { return p.ln.Addr().String() }

func (p *dropOnceProxy) Close() {
	select {
	case <-p.closed:
		return
	default:
		close(p.closed)
		_ = p.ln.Close()
		p.wg.Wait()
	}
}

func (p *dropOnceProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(client)
		}()
	}
}

func (p *dropOnceProxy) handle(client net.Conn) {
	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()

	first, err := protocol.ReadMessage(client)
	if err != nil {
		return
	}
	if err := protocol.WriteMessage(upstream, first); err != nil {
		return
	}

	dropThis := first.Type == protocol.TypeCreate && p.dropped.CompareAndSwap(false, true)
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() {
		once.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
			close(done)
		})
	}

	go func() {
		_, _ = io.Copy(client, upstream)
		closeBoth()
	}()

	if dropThis {
		_, _ = io.CopyN(upstream, client, p.dropAfter)
		closeBoth()
	} else {
		_, _ = io.Copy(upstream, client)
		closeBoth()
	}
	<-done
}
