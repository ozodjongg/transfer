package transfer

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeSTUNServer struct {
	conn *net.UDPConn
	wg   sync.WaitGroup
}

func startFakeSTUNServer(t *testing.T) *fakeSTUNServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSTUNServer{conn: conn}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != stunBindingRequest || binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
				continue
			}
			var tx [12]byte
			copy(tx[:], buf[8:20])
			resp := makeSTUNBindingResponse(t, tx, from)
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	return s
}
func (s *fakeSTUNServer) Addr() string { return s.conn.LocalAddr().String() }
func (s *fakeSTUNServer) Close()       { _ = s.conn.Close(); s.wg.Wait() }

func TestV8InternetP2PBypassesRelayPayload(t *testing.T) {
	stun := startFakeSTUNServer(t)
	defer stun.Close()

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

	// If the clients accidentally fall back to the relay for payload, this proxy
	// observes data_send connections. P2P success must keep this at zero.
	proxy := newDropDataOnceProxy(t, serverAddr, 1)
	defer proxy.Close()

	src := t.TempDir()
	folder := filepath.Join(src, "P2P")
	if err := os.MkdirAll(filepath.Join(folder, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	data1 := bytes.Repeat([]byte("internet-p2p-A-"), 90000)
	data2 := bytes.Repeat([]byte("internet-p2p-B-"), 70000)
	if err := os.WriteFile(filepath.Join(folder, "a.bin"), data1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "nested", "b.bin"), data2, 0o600); err != nil {
		t.Fatal(err)
	}

	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	base := ClientConfig{
		Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 30 * time.Second,
		LANDirect: false, InternetP2P: true, STUNServers: []string{stun.Addr()},
		P2PDiscoveryTimeout: time.Second, P2PConnectTimeout: 3 * time.Second, ParallelStreams: 4,
	}
	sendCfg := base
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
		t.Fatal("no transfer code")
	}
	recvErr := make(chan error, 1)
	go func() { _, err := ReceiveTransfer(base, code, recvDir); recvErr <- err }()

	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("sender: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("sender timeout")
	}
	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("receiver timeout")
	}

	got1, err := os.ReadFile(filepath.Join(recvDir, "P2P", "a.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := os.ReadFile(filepath.Join(recvDir, "P2P", "nested", "b.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, data1) || !bytes.Equal(got2, data2) {
		t.Fatal("P2P output mismatch")
	}
	if n := proxy.dataSends.Load(); n != 0 {
		t.Fatalf("P2P unexpectedly used public relay payload streams: %d", n)
	}
}

func TestV8InternetP2PDiscoveryFailureFallsBackToRelay(t *testing.T) {
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

	proxy := newDropDataOnceProxy(t, serverAddr, 1<<30) // count streams; don't actually reach drop threshold
	defer proxy.Close()

	src := t.TempDir()
	file := filepath.Join(src, "fallback.bin")
	data := bytes.Repeat([]byte("relay-fallback-"), 50000)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	cfg := ClientConfig{
		Addr: proxy.Addr(), ConnectTimeout: time.Second, IOTimeout: 20 * time.Second,
		LANDirect: false, InternetP2P: true, STUNServers: []string{"127.0.0.1:9"},
		P2PDiscoveryTimeout: 60 * time.Millisecond, P2PConnectTimeout: 300 * time.Millisecond,
		ParallelStreams: 4,
	}
	sendCfg := cfg
	sendCfg.OnTransferCode = func(code string) {
		select {
		case codeCh <- code:
		default:
		}
	}
	sendErr := make(chan error, 1)
	go func() { _, err := SendPaths(sendCfg, []string{file}); sendErr <- err }()
	var code string
	select {
	case code = <-codeCh:
	case <-time.After(4 * time.Second):
		t.Fatal("no code")
	}
	recvErr := make(chan error, 1)
	go func() { _, err := ReceiveTransfer(cfg, code, recvDir); recvErr <- err }()
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
	got, err := os.ReadFile(filepath.Join(recvDir, "fallback.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("fallback output mismatch")
	}
	if n := proxy.dataSends.Load(); n < 2 {
		t.Fatalf("expected relay payload streams after P2P discovery failure, got %d", n)
	}
}

func TestV8InternetP2PHardFailureFallsBackToRelay(t *testing.T) {
	stun := startFakeSTUNServer(t)
	defer stun.Close()

	serverAddr := freeTCPAddr(t)
	server := NewServer(ServerConfig{
		Addr: serverAddr, RoomTTL: 15 * time.Second, TransferTimeout: 45 * time.Second,
		ResumeGrace: 15 * time.Second, MaxTransferSize: 64 << 20, MaxEncryptedManifest: 2 << 20,
		MaxConnections: 96, MaxHandshakesPerMinute: 5000,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	go server.ListenAndServe()
	defer server.Shutdown()
	waitForTCP(t, serverAddr)

	// Count relay data streams. The transfer must first select P2P, fail after
	// some real payload bytes, and then restart safely through public relay.
	proxy := newDropDataOnceProxy(t, serverAddr, 1<<30)
	defer proxy.Close()

	src := t.TempDir()
	file := filepath.Join(src, "p2p-hard-fallback.bin")
	data := bytes.Repeat([]byte("forced-p2p-hard-failure-"), 180000) // ~4 MiB
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	recvDir := t.TempDir()
	codeCh := make(chan string, 1)
	base := ClientConfig{
		Addr: proxy.Addr(), ConnectTimeout: 2 * time.Second, IOTimeout: 40 * time.Second,
		LANDirect: false, InternetP2P: true, STUNServers: []string{stun.Addr()},
		P2PDiscoveryTimeout: time.Second, P2PConnectTimeout: 3 * time.Second, ParallelStreams: 4,
	}
	sendCfg := base
	// Enough bytes for PAKE/direct control + more than one encrypted file chunk,
	// but far below the complete payload.
	sendCfg.testP2PFailAfterBytes = 900 << 10
	sendCfg.OnTransferCode = func(code string) {
		select {
		case codeCh <- code:
		default:
		}
	}

	sendErr := make(chan error, 1)
	go func() { _, err := SendPaths(sendCfg, []string{file}); sendErr <- err }()
	var code string
	select {
	case code = <-codeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no transfer code")
	}
	recvErr := make(chan error, 1)
	go func() { _, err := ReceiveTransfer(base, code, recvDir); recvErr <- err }()

	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("sender: %v", err)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("sender timeout")
	}
	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("receiver timeout")
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "p2p-hard-fallback.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("hard-fallback output mismatch")
	}
	if n := proxy.dataSends.Load(); n < 2 {
		t.Fatalf("expected relay payload streams after selected P2P hard failure, got %d", n)
	}
}
