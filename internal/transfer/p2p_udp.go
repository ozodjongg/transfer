package transfer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	p2pPacketMagic   = "PT8U"
	p2pHeaderSize    = 24
	p2pMACSize       = 16
	p2pMaxDatagram   = 1200
	p2pMaxPayload    = p2pMaxDatagram - p2pHeaderSize - p2pMACSize
	p2pSendWindow    = 256
	p2pMaxPending    = 4096
	p2pRetransmitRTO = 180 * time.Millisecond
	p2pMaxRTOs       = 80

	p2pTypePunch    = byte(1)
	p2pTypePunchAck = byte(2)
	p2pTypeData     = byte(3)
	p2pTypeAck      = byte(4)
	p2pTypeClose    = byte(5)
)

type p2pPeer struct {
	udp       *net.UDPConn
	advertise string
	mu        sync.Mutex
	used      bool
}

func prepareP2PPeer(cfg ClientConfig) (*p2pPeer, error) {
	servers := append([]string(nil), cfg.STUNServers...)
	if len(servers) == 0 {
		servers = []string{"stun.l.google.com:19302"}
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("P2P UDP listen: %w", err)
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	timeout := cfg.P2PDiscoveryTimeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	var lastErr error
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		addr, derr := discoverSTUNEndpoint(udp, server, timeout)
		if derr == nil {
			return &p2pPeer{udp: udp, advertise: addr.String()}, nil
		}
		lastErr = derr
	}
	_ = udp.Close()
	if lastErr == nil {
		lastErr = errors.New("STUN server configured emas")
	}
	return nil, lastErr
}

func (p *p2pPeer) Endpoint() string {
	if p == nil {
		return ""
	}
	return p.advertise
}

func (p *p2pPeer) Close() error {
	if p == nil || p.udp == nil {
		return nil
	}
	return p.udp.Close()
}

func (p *p2pPeer) Establish(secret []byte, room, remote string, timeout time.Duration) (net.Conn, error) {
	if p == nil || p.udp == nil {
		return nil, errors.New("P2P peer tayyor emas")
	}
	remoteAddr, err := sanitizeP2PEndpoint(remote)
	if err != nil {
		return nil, err
	}
	if len(secret) != transferSecretSize {
		return nil, errors.New("P2P transfer secret invalid")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	p.mu.Lock()
	if p.used {
		p.mu.Unlock()
		return nil, errors.New("P2P UDP socket already used")
	}
	p.used = true
	p.mu.Unlock()

	key := hkdfSHA256(secret, "internet-p2p-packet-auth", 32)
	sessionID := hkdfSHA256(secret, "internet-p2p-session-id/"+strings.ToUpper(strings.TrimSpace(room)), 8)
	actualRemote, err := punchUDP(p.udp, remoteAddr, key, sessionID, timeout)
	if err != nil {
		return nil, err
	}
	return newUDPReliableConn(p.udp, actualRemote, key, sessionID), nil
}

func sanitizeP2PEndpoint(endpoint string) (*net.UDPAddr, error) {
	endpoint = strings.TrimSpace(endpoint)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, errors.New("P2P endpoint invalid")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, errors.New("P2P endpoint IP invalid")
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
	if err != nil || addr.Port <= 0 || addr.Port > 65535 {
		return nil, errors.New("P2P endpoint port invalid")
	}
	return addr, nil
}

type p2pPacket struct {
	typ       byte
	seq       uint32
	ack       uint32
	sessionID [8]byte
	payload   []byte
}

func encodeP2PPacket(key, session []byte, typ byte, seq, ack uint32, payload []byte) ([]byte, error) {
	if len(session) != 8 || len(payload) > p2pMaxPayload {
		return nil, errors.New("P2P packet parameters invalid")
	}
	pkt := make([]byte, p2pHeaderSize+len(payload)+p2pMACSize)
	copy(pkt[0:4], []byte(p2pPacketMagic))
	pkt[4] = typ
	pkt[5] = 0
	binary.BigEndian.PutUint16(pkt[6:8], uint16(len(payload)))
	binary.BigEndian.PutUint32(pkt[8:12], seq)
	binary.BigEndian.PutUint32(pkt[12:16], ack)
	copy(pkt[16:24], session)
	copy(pkt[p2pHeaderSize:], payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(pkt[:len(pkt)-p2pMACSize])
	sum := mac.Sum(nil)
	copy(pkt[len(pkt)-p2pMACSize:], sum[:p2pMACSize])
	return pkt, nil
}

func decodeP2PPacket(key, session, pkt []byte) (p2pPacket, error) {
	var out p2pPacket
	if len(pkt) < p2pHeaderSize+p2pMACSize || string(pkt[0:4]) != p2pPacketMagic {
		return out, errors.New("not P2P packet")
	}
	if len(session) != 8 || !hmac.Equal(pkt[16:24], session) {
		return out, errors.New("P2P session mismatch")
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[6:8]))
	if payloadLen > p2pMaxPayload || p2pHeaderSize+payloadLen+p2pMACSize != len(pkt) {
		return out, errors.New("P2P packet size invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(pkt[:len(pkt)-p2pMACSize])
	expected := mac.Sum(nil)
	if !hmac.Equal(expected[:p2pMACSize], pkt[len(pkt)-p2pMACSize:]) {
		return out, errors.New("P2P packet authentication failed")
	}
	out.typ = pkt[4]
	out.seq = binary.BigEndian.Uint32(pkt[8:12])
	out.ack = binary.BigEndian.Uint32(pkt[12:16])
	copy(out.sessionID[:], pkt[16:24])
	out.payload = append([]byte(nil), pkt[p2pHeaderSize:p2pHeaderSize+payloadLen]...)
	return out, nil
}

func punchUDP(udp *net.UDPConn, advertised *net.UDPAddr, key, session []byte, timeout time.Duration) (*net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	punch, _ := encodeP2PPacket(key, session, p2pTypePunch, 0, 0, nil)
	ack, _ := encodeP2PPacket(key, session, p2pTypePunchAck, 0, 0, nil)
	buf := make([]byte, p2pMaxDatagram+128)
	nextSend := time.Time{}
	for time.Now().Before(deadline) {
		now := time.Now()
		if nextSend.IsZero() || !now.Before(nextSend) {
			_, _ = udp.WriteToUDP(punch, advertised)
			nextSend = now.Add(90 * time.Millisecond)
		}
		readUntil := nextSend
		if readUntil.After(deadline) {
			readUntil = deadline
		}
		_ = udp.SetReadDeadline(readUntil)
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		msg, err := decodeP2PPacket(key, session, buf[:n])
		if err != nil {
			continue
		}
		if msg.typ != p2pTypePunch && msg.typ != p2pTypePunchAck {
			continue
		}
		// The authenticated source address is authoritative. This also tolerates
		// a NAT that returns a slightly different endpoint than the STUN server
		// observed, as long as a packet actually reaches us.
		for i := 0; i < 3; i++ {
			_, _ = udp.WriteToUDP(ack, from)
		}
		_ = udp.SetReadDeadline(time.Time{})
		return from, nil
	}
	_ = udp.SetReadDeadline(time.Time{})
	return nil, errors.New("Internet P2P hole-punch timeout")
}

// failAfterWriteConn is an internal deterministic fault injector used only by
// package integration tests. It preserves the real P2P transport until the
// configured byte budget is exhausted, then simulates a hard network failure.
type failAfterWriteConn struct {
	net.Conn
	remaining int64
}

func (c *failAfterWriteConn) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errors.New("forced P2P transport failure")
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Write(p)
	c.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	if c.remaining <= 0 {
		return n, errors.New("forced P2P transport failure")
	}
	return n, nil
}

type p2pSegment struct {
	seq  uint32
	data []byte
}

type udpReliableConn struct {
	udp       *net.UDPConn
	remoteMu  sync.RWMutex
	remote    *net.UDPAddr
	key       []byte
	sessionID []byte

	sendMu  sync.Mutex
	sendSeq uint32
	ackCh   chan uint32

	recvMu      sync.Mutex
	recvNext    uint32
	recvPending map[uint32][]byte
	recvBuf     bytes.Buffer
	dataReady   chan struct{}

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	closed    chan struct{}
	closeOnce sync.Once
	remoteEOF bool

	// Deterministic packet-loss injection for package tests only.
	testDropEveryData uint32
	testDataPackets   atomic.Uint32
}

func newUDPReliableConn(udp *net.UDPConn, remote *net.UDPAddr, key, session []byte) *udpReliableConn {
	c := &udpReliableConn{
		udp: udp, remote: remote, key: append([]byte(nil), key...), sessionID: append([]byte(nil), session...),
		sendSeq: 1, recvNext: 1, ackCh: make(chan uint32, 4096), recvPending: make(map[uint32][]byte),
		dataReady: make(chan struct{}, 1), closed: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *udpReliableConn) signalData() {
	select {
	case c.dataReady <- struct{}{}:
	default:
	}
}

func (c *udpReliableConn) getRemote() *net.UDPAddr {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	if c.remote == nil {
		return nil
	}
	cp := *c.remote
	cp.IP = append(net.IP(nil), c.remote.IP...)
	return &cp
}

func (c *udpReliableConn) setRemote(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	c.remoteMu.Lock()
	cp := *addr
	cp.IP = append(net.IP(nil), addr.IP...)
	c.remote = &cp
	c.remoteMu.Unlock()
}

func (c *udpReliableConn) sendPacket(typ byte, seq, ack uint32, payload []byte) error {
	if typ == p2pTypeData && c.testDropEveryData > 0 {
		n := c.testDataPackets.Add(1)
		if n%c.testDropEveryData == 0 {
			return nil
		}
	}
	pkt, err := encodeP2PPacket(c.key, c.sessionID, typ, seq, ack, payload)
	if err != nil {
		return err
	}
	remote := c.getRemote()
	if remote == nil {
		return errors.New("P2P remote missing")
	}
	_, err = c.udp.WriteToUDP(pkt, remote)
	return err
}

func (c *udpReliableConn) readLoop() {
	buf := make([]byte, p2pMaxDatagram+128)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
			}
			// UDP read deadlines are intentionally not used by the stream layer;
			// logical read deadlines are implemented in Read().
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			c.closeWithEOF()
			return
		}
		msg, err := decodeP2PPacket(c.key, c.sessionID, buf[:n])
		if err != nil {
			continue
		}
		c.setRemote(from) // authenticated NAT rebinding support
		switch msg.typ {
		case p2pTypeData:
			c.handleData(msg.seq, msg.payload)
		case p2pTypeAck:
			select {
			case c.ackCh <- msg.ack:
			default:
			}
		case p2pTypeClose:
			c.recvMu.Lock()
			c.remoteEOF = true
			c.recvMu.Unlock()
			c.signalData()
		}
	}
}

func (c *udpReliableConn) handleData(seq uint32, payload []byte) {
	c.recvMu.Lock()
	if seq < c.recvNext {
		ack := c.recvNext - 1
		c.recvMu.Unlock()
		_ = c.sendPacket(p2pTypeAck, 0, ack, nil)
		return
	}
	if seq-c.recvNext > p2pMaxPending {
		ack := c.recvNext - 1
		c.recvMu.Unlock()
		_ = c.sendPacket(p2pTypeAck, 0, ack, nil)
		return
	}
	if _, exists := c.recvPending[seq]; !exists {
		c.recvPending[seq] = append([]byte(nil), payload...)
	}
	advanced := false
	for {
		p, ok := c.recvPending[c.recvNext]
		if !ok {
			break
		}
		delete(c.recvPending, c.recvNext)
		_, _ = c.recvBuf.Write(p)
		c.recvNext++
		advanced = true
	}
	ack := c.recvNext - 1
	c.recvMu.Unlock()
	_ = c.sendPacket(p2pTypeAck, 0, ack, nil)
	if advanced {
		c.signalData()
	}
}

func (c *udpReliableConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.recvMu.Lock()
		if c.recvBuf.Len() > 0 {
			n, _ := c.recvBuf.Read(p)
			c.recvMu.Unlock()
			return n, nil
		}
		eof := c.remoteEOF
		c.recvMu.Unlock()
		if eof {
			return 0, io.EOF
		}
		deadline := c.getReadDeadline()
		var timer <-chan time.Time
		var t *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, timeoutError("read")
			}
			t = time.NewTimer(d)
			timer = t.C
		}
		select {
		case <-c.dataReady:
			if t != nil {
				t.Stop()
			}
			continue
		case <-c.closed:
			if t != nil {
				t.Stop()
			}
			return 0, net.ErrClosed
		case <-timer:
			return 0, timeoutError("read")
		}
	}
}

func (c *udpReliableConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	segments := make([]p2pSegment, 0, (len(p)+p2pMaxPayload-1)/p2pMaxPayload)
	for off := 0; off < len(p); {
		end := off + p2pMaxPayload
		if end > len(p) {
			end = len(p)
		}
		segments = append(segments, p2pSegment{seq: c.sendSeq, data: p[off:end]})
		c.sendSeq++
		off = end
	}
	base, next := 0, 0
	rtos := 0
	sendOne := func(s p2pSegment) error { return c.sendPacket(p2pTypeData, s.seq, 0, s.data) }
	fillWindow := func() error {
		for next < len(segments) && next-base < p2pSendWindow {
			if err := sendOne(segments[next]); err != nil {
				return err
			}
			next++
			if next%64 == 0 {
				time.Sleep(150 * time.Microsecond)
			}
		}
		return nil
	}
	if err := fillWindow(); err != nil {
		return 0, err
	}
	for base < len(segments) {
		deadline := c.getWriteDeadline()
		wait := p2pRetransmitRTO
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left <= 0 {
				return byteCountBefore(segments, base), timeoutError("write")
			}
			if left < wait {
				wait = left
			}
		}
		timer := time.NewTimer(wait)
		select {
		case ack := <-c.ackCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			oldBase := base
			for base < len(segments) && segments[base].seq <= ack {
				base++
			}
			if base > oldBase {
				rtos = 0
				if err := fillWindow(); err != nil {
					return byteCountBefore(segments, base), err
				}
			}
		case <-timer.C:
			rtos++
			if rtos > p2pMaxRTOs {
				return byteCountBefore(segments, base), errors.New("Internet P2P peer javob bermayapti")
			}
			// Cumulative ACK + receiver out-of-order cache means a lost packet can
			// stall the ACK frontier. Retransmitting only the active window is
			// bounded and lets the frontier jump forward as soon as the gap closes.
			for i := base; i < next; i++ {
				if err := sendOne(segments[i]); err != nil {
					return byteCountBefore(segments, base), err
				}
				if (i-base+1)%64 == 0 {
					time.Sleep(150 * time.Microsecond)
				}
			}
		case <-c.closed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return byteCountBefore(segments, base), net.ErrClosed
		}
	}
	return len(p), nil
}

func byteCountBefore(segments []p2pSegment, base int) int {
	n := 0
	for i := 0; i < base && i < len(segments); i++ {
		n += len(segments[i].data)
	}
	return n
}

type p2pTimeoutError string

func (e p2pTimeoutError) Error() string   { return string(e) + " timeout" }
func (e p2pTimeoutError) Timeout() bool   { return true }
func (e p2pTimeoutError) Temporary() bool { return true }
func timeoutError(op string) error        { return p2pTimeoutError(op) }

func (c *udpReliableConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.sendPacket(p2pTypeClose, 0, 0, nil)
		close(c.closed)
		_ = c.udp.Close()
		c.signalData()
	})
	return nil
}

func (c *udpReliableConn) closeWithEOF() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.signalData()
	})
}

func (c *udpReliableConn) LocalAddr() net.Addr  { return c.udp.LocalAddr() }
func (c *udpReliableConn) RemoteAddr() net.Addr { return c.getRemote() }

func (c *udpReliableConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.signalData()
	return nil
}
func (c *udpReliableConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	c.signalData()
	return nil
}
func (c *udpReliableConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}
func (c *udpReliableConn) getReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}
func (c *udpReliableConn) getWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}

func effectiveP2PConnectTimeout(cfg ClientConfig) time.Duration {
	if cfg.P2PConnectTimeout > 0 {
		return cfg.P2PConnectTimeout
	}
	return 5 * time.Second
}
