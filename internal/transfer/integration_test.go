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

func TestV5MultiFileFolderEncryptedTransferWithResume(t *testing.T) {
	serverAddr := freeTCPAddr(t)
	server := NewServer(ServerConfig{
		Addr: serverAddr, RoomTTL: 10 * time.Second, TransferTimeout: 30 * time.Second,
		ResumeGrace: 10 * time.Second, MaxTransferSize: 64 << 20, MaxEncryptedManifest: 2 << 20,
		MaxConnections: 32, MaxHandshakesPerMinute: 1000,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	defer server.Shutdown()
	waitForTCP(t, serverAddr)

	// Drop the first sender stream after > one encrypted chunk so receiver has
	// an authenticated chunk boundary to resume from.
	proxy := newDropOnceProxy(t, serverAddr, 900*1024)
	defer proxy.Close()

	srcBase := t.TempDir()
	f1 := filepath.Join(srcBase, "report.txt")
	data1 := bytes.Repeat([]byte("report-data-"), 90000) // > 1 MiB
	if err := os.WriteFile(f1, data1, 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(srcBase, "Project")
	if err := os.MkdirAll(filepath.Join(folder, "sub", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	data2 := bytes.Repeat([]byte("nested-data-"), 70000)
	if err := os.WriteFile(filepath.Join(folder, "sub", "nested.bin"), data2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "zero.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	sendCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second, OnTransferCode: func(code string) {
		select {
		case codeCh <- code:
		default:
		}
	}}
	recvCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second}

	type result struct {
		paths []string
		err   error
	}
	sendResult := make(chan error, 1)
	go func() { _, err := SendPaths(sendCfg, []string{f1, folder}); sendResult <- err }()

	var code string
	select {
	case code = <-codeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not create transfer code")
	}

	recvResult := make(chan result, 1)
	go func() { p, err := ReceiveTransfer(recvCfg, code, recvDir); recvResult <- result{p, err} }()

	select {
	case err := <-sendResult:
		if err != nil {
			t.Fatalf("sender: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("sender timeout")
	}
	var paths []string
	select {
	case r := <-recvResult:
		if r.err != nil {
			t.Fatalf("receiver: %v", r.err)
		}
		paths = r.paths
	case <-time.After(20 * time.Second):
		t.Fatal("receiver timeout")
	}
	if len(paths) != 2 {
		t.Fatalf("final roots=%v", paths)
	}

	got1, err := os.ReadFile(filepath.Join(recvDir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, data1) {
		t.Fatal("report mismatch")
	}
	got2, err := os.ReadFile(filepath.Join(recvDir, "Project", "sub", "nested.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, data2) {
		t.Fatal("nested mismatch")
	}
	if st, err := os.Stat(filepath.Join(recvDir, "Project", "sub", "empty")); err != nil || !st.IsDir() {
		t.Fatal("empty directory missing")
	}
	if st, err := os.Stat(filepath.Join(recvDir, "Project", "zero.txt")); err != nil || st.Size() != 0 {
		t.Fatal("zero file missing")
	}
	if !proxy.dropped.Load() {
		t.Fatal("proxy did not force disconnect")
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server stopped: %v", err)
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
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server not ready: %s", addr)
}

type dropOnceProxy struct {
	ln        net.Listener
	target    string
	dropAfter int64
	dropped   atomic.Bool
	wg        sync.WaitGroup
}

func newDropOnceProxy(t *testing.T, target string, dropAfter int64) *dropOnceProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &dropOnceProxy{ln: ln, target: target, dropAfter: dropAfter}
	p.wg.Add(1)
	go p.acceptLoop()
	return p
}
func (p *dropOnceProxy) Addr() string { return p.ln.Addr().String() }
func (p *dropOnceProxy) Close()       { _ = p.ln.Close(); p.wg.Wait() }
func (p *dropOnceProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.handle(c) }()
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
	closeBoth := func() { once.Do(func() { _ = client.Close(); _ = upstream.Close(); close(done) }) }
	go func() { _, _ = io.Copy(client, upstream); closeBoth() }()
	if dropThis {
		_, _ = io.CopyN(upstream, client, p.dropAfter)
		closeBoth()
	} else {
		_, _ = io.Copy(upstream, client)
		closeBoth()
	}
	<-done
}

func TestV6ParallelPublicTransferWithDataStreamResume(t *testing.T) {
	serverAddr := freeTCPAddr(t)
	server := NewServer(ServerConfig{
		Addr: serverAddr, RoomTTL: 10 * time.Second, TransferTimeout: 30 * time.Second,
		ResumeGrace: 10 * time.Second, MaxTransferSize: 128 << 20, MaxEncryptedManifest: 2 << 20,
		MaxConnections: 64, MaxHandshakesPerMinute: 5000,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	go server.ListenAndServe()
	defer server.Shutdown()
	waitForTCP(t, serverAddr)

	proxy := newDropDataOnceProxy(t, serverAddr, 700*1024)
	defer proxy.Close()

	src := t.TempDir()
	folder := filepath.Join(src, "Parallel")
	if err := os.MkdirAll(filepath.Join(folder, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	data1 := bytes.Repeat([]byte("parallel-A-"), 500000) // ~5 MiB
	data2 := bytes.Repeat([]byte("parallel-B-"), 450000)
	if err := os.WriteFile(filepath.Join(folder, "a.bin"), data1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "nested", "b.bin"), data2, 0o600); err != nil {
		t.Fatal(err)
	}

	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	baseCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second, LANDirect: false, ParallelStreams: 4}
	sendCfg := baseCfg
	sendCfg.OnTransferCode = func(code string) {
		select {
		case codeCh <- code:
		default:
		}
	}

	sendErr := make(chan error, 1)
	go func() { _, err := SendPaths(sendCfg, []string{folder}); sendErr <- err }()
	var code string
	select {
	case code = <-codeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no code")
	}
	recvErr := make(chan error, 1)
	go func() { _, err := ReceiveTransfer(baseCfg, code, recvDir); recvErr <- err }()

	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("sender: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("sender timeout")
	}
	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("receiver timeout")
	}

	got1, err := os.ReadFile(filepath.Join(recvDir, "Parallel", "a.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := os.ReadFile(filepath.Join(recvDir, "Parallel", "nested", "b.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, data1) || !bytes.Equal(got2, data2) {
		t.Fatal("parallel output mismatch")
	}
	if !proxy.dropped.Load() {
		t.Fatal("proxy did not drop a data stream")
	}
	if proxy.dataSends.Load() < 4 {
		t.Fatalf("expected parallel data streams, got %d", proxy.dataSends.Load())
	}
}

func TestV6LANDirectBypassesPublicPayload(t *testing.T) {
	serverAddr := freeTCPAddr(t)
	server := NewServer(ServerConfig{
		Addr: serverAddr, RoomTTL: 10 * time.Second, TransferTimeout: 30 * time.Second,
		ResumeGrace: 10 * time.Second, MaxTransferSize: 64 << 20, MaxEncryptedManifest: 2 << 20,
		MaxConnections: 64, MaxHandshakesPerMinute: 5000,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	go server.ListenAndServe()
	defer server.Shutdown()
	waitForTCP(t, serverAddr)

	proxy := newDropDataOnceProxy(t, serverAddr, 1)
	defer proxy.Close()

	src := t.TempDir()
	file := filepath.Join(src, "lan.bin")
	data := bytes.Repeat([]byte("LAN-DIRECT-"), 250000)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	sendCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second, LANDirect: true, ParallelStreams: 4, OnTransferCode: func(code string) {
		select {
		case codeCh <- code:
		default:
		}
	}}
	recvCfg := ClientConfig{Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second, LANDirect: true, ParallelStreams: 4}

	sendErr := make(chan error, 1)
	go func() { _, err := SendPaths(sendCfg, []string{file}); sendErr <- err }()
	var code string
	select {
	case code = <-codeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no code")
	}
	recvErr := make(chan error, 1)
	go func() { _, err := ReceiveTransfer(recvCfg, code, recvDir); recvErr <- err }()
	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("sender: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("sender timeout")
	}
	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("receiver timeout")
	}
	got, err := os.ReadFile(filepath.Join(recvDir, "lan.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("LAN output mismatch")
	}
	if n := proxy.dataSends.Load(); n != 0 {
		t.Fatalf("LAN direct unexpectedly used public payload streams: %d", n)
	}
}

type dropDataOnceProxy struct {
	ln        net.Listener
	target    string
	dropAfter int64
	dropped   atomic.Bool
	dataSends atomic.Int32
	wg        sync.WaitGroup
}

func newDropDataOnceProxy(t *testing.T, target string, dropAfter int64) *dropDataOnceProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &dropDataOnceProxy{ln: ln, target: target, dropAfter: dropAfter}
	p.wg.Add(1)
	go p.acceptLoop()
	return p
}
func (p *dropDataOnceProxy) Addr() string { return p.ln.Addr().String() }
func (p *dropDataOnceProxy) Close()       { _ = p.ln.Close(); p.wg.Wait() }
func (p *dropDataOnceProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.handle(c) }()
	}
}
func (p *dropDataOnceProxy) handle(client net.Conn) {
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
	dropThis := false
	if first.Type == protocol.TypeDataSend {
		p.dataSends.Add(1)
		dropThis = p.dropped.CompareAndSwap(false, true)
	}
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { _ = client.Close(); _ = upstream.Close(); close(done) }) }
	go func() { _, _ = io.Copy(client, upstream); closeBoth() }()
	if dropThis {
		// Preserve the server's data-stream acknowledgement first. Client payload
		// begins only after it receives that acknowledgement.
		time.Sleep(20 * time.Millisecond)
		_, _ = io.CopyN(upstream, client, p.dropAfter)
		closeBoth()
	} else {
		_, _ = io.Copy(upstream, client)
		closeBoth()
	}
	<-done
}
