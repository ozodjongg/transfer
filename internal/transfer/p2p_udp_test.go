package transfer

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSTUNXORMappedRoundTrip(t *testing.T) {
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	mapped := &net.UDPAddr{IP: net.ParseIP("203.0.113.45").To4(), Port: 54321}
	pkt := makeSTUNBindingResponse(t, tx, mapped)
	got, ok, err := parseSTUNBindingResponse(pkt, tx)
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	if got.Port != mapped.Port || !got.IP.Equal(mapped.IP) {
		t.Fatalf("mapped=%v want=%v", got, mapped)
	}
}

func TestUDPReliableConnBidirectional(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := generateTransferSecret()
	key := hkdfSHA256(secret, "internet-p2p-packet-auth", 32)
	sid := hkdfSHA256(secret, "internet-p2p-session-id/TESTROOM", 8)
	ca := newUDPReliableConn(a, b.LocalAddr().(*net.UDPAddr), key, sid)
	cb := newUDPReliableConn(b, a.LocalAddr().(*net.UDPAddr), key, sid)
	defer ca.Close()
	defer cb.Close()

	payload := bytes.Repeat([]byte("udp-p2p-transfer-"), 90000) // > 1 MiB
	errCh := make(chan error, 1)
	go func() {
		_, err := ca.Write(payload)
		errCh <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cb, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}

	reply := bytes.Repeat([]byte("ack-back-"), 1000)
	go func() { _, _ = cb.Write(reply) }()
	gotReply := make([]byte, len(reply))
	if _, err := io.ReadFull(ca, gotReply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatal("reply mismatch")
	}
}

func TestUDPReliableConnRecoversFromPacketLoss(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := generateTransferSecret()
	key := hkdfSHA256(secret, "internet-p2p-packet-auth", 32)
	sid := hkdfSHA256(secret, "internet-p2p-session-id/LOSSROOM", 8)
	ca := newUDPReliableConn(a, b.LocalAddr().(*net.UDPAddr), key, sid)
	cb := newUDPReliableConn(b, a.LocalAddr().(*net.UDPAddr), key, sid)
	defer ca.Close()
	defer cb.Close()

	// Lose every seventh outbound DATA datagram. The cumulative ACK/retransmit
	// path must still reconstruct the exact ordered byte stream.
	ca.testDropEveryData = 7
	payload := bytes.Repeat([]byte("loss-recovery-"), 18000)
	errCh := make(chan error, 1)
	go func() {
		_, err := ca.Write(payload)
		errCh <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cb, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after packet loss")
	}
}

func TestAuthenticatedUDPHolePunch(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	secret, _ := generateTransferSecret()
	key := hkdfSHA256(secret, "internet-p2p-packet-auth", 32)
	sid := hkdfSHA256(secret, "internet-p2p-session-id/ROOM", 8)
	var wg sync.WaitGroup
	wg.Add(2)
	var ra, rb *net.UDPAddr
	var ea, eb error
	go func() { defer wg.Done(); ra, ea = punchUDP(a, b.LocalAddr().(*net.UDPAddr), key, sid, 2*time.Second) }()
	go func() { defer wg.Done(); rb, eb = punchUDP(b, a.LocalAddr().(*net.UDPAddr), key, sid, 2*time.Second) }()
	wg.Wait()
	if ea != nil || eb != nil {
		t.Fatalf("punch errors: %v / %v", ea, eb)
	}
	if ra == nil || rb == nil {
		t.Fatal("missing remote")
	}
}

func makeSTUNBindingResponse(t *testing.T, tx [12]byte, mapped *net.UDPAddr) []byte {
	t.Helper()
	ip := mapped.IP.To4()
	if ip == nil {
		t.Fatal("test helper only IPv4")
	}
	value := make([]byte, 8)
	value[1] = 0x01
	binary.BigEndian.PutUint16(value[2:4], uint16(mapped.Port)^uint16(stunMagicCookie>>16))
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
	for i := 0; i < 4; i++ {
		value[4+i] = ip[i] ^ cookie[i]
	}
	pkt := make([]byte, 20+4+len(value))
	binary.BigEndian.PutUint16(pkt[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(value)))
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	copy(pkt[8:20], tx[:])
	binary.BigEndian.PutUint16(pkt[20:22], stunAttrXORMapped)
	binary.BigEndian.PutUint16(pkt[22:24], uint16(len(value)))
	copy(pkt[24:], value)
	return pkt
}
