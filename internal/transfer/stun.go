package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunMagicCookie     = 0x2112A442
	stunAttrMapped      = 0x0001
	stunAttrXORMapped   = 0x0020
)

// discoverSTUNEndpoint asks a STUN server for the public address of the exact
// UDP socket that will later be used for hole punching. Reusing the same socket
// is essential: opening a second UDP socket would usually create a different
// NAT mapping.
func discoverSTUNEndpoint(conn *net.UDPConn, server string, timeout time.Duration) (*net.UDPAddr, error) {
	if conn == nil {
		return nil, errors.New("STUN UDP socket is nil")
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN %q: %w", server, err)
	}

	var tx [12]byte
	if _, err := io.ReadFull(rand.Reader, tx[:]); err != nil {
		return nil, err
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(request[2:4], 0)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	copy(request[8:20], tx[:])

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.WriteToUDP(request, serverAddr); err != nil {
		return nil, fmt.Errorf("STUN request: %w", err)
	}

	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("STUN response: %w", err)
		}
		addr, ok, err := parseSTUNBindingResponse(buf[:n], tx)
		if err != nil {
			continue // ignore unrelated or malformed UDP datagrams until deadline
		}
		if ok {
			return addr, nil
		}
	}
}

func parseSTUNBindingResponse(pkt []byte, tx [12]byte) (*net.UDPAddr, bool, error) {
	if len(pkt) < 20 {
		return nil, false, errors.New("short STUN packet")
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != stunBindingResponse {
		return nil, false, errors.New("not STUN binding response")
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if msgLen+20 > len(pkt) {
		return nil, false, errors.New("truncated STUN response")
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return nil, false, errors.New("invalid STUN magic cookie")
	}
	for i := 0; i < len(tx); i++ {
		if pkt[8+i] != tx[i] {
			return nil, false, errors.New("STUN transaction mismatch")
		}
	}

	var mapped *net.UDPAddr
	end := 20 + msgLen
	for off := 20; off+4 <= end; {
		attrType := binary.BigEndian.Uint16(pkt[off : off+2])
		attrLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		valueStart := off + 4
		valueEnd := valueStart + attrLen
		if valueEnd > end {
			return nil, false, errors.New("truncated STUN attribute")
		}
		value := pkt[valueStart:valueEnd]
		var addr *net.UDPAddr
		var err error
		switch attrType {
		case stunAttrXORMapped:
			addr, err = parseSTUNAddress(value, true, tx)
		case stunAttrMapped:
			addr, err = parseSTUNAddress(value, false, tx)
		}
		if err == nil && addr != nil {
			if attrType == stunAttrXORMapped {
				return addr, true, nil
			}
			mapped = addr
		}
		off = valueEnd
		if rem := off % 4; rem != 0 {
			off += 4 - rem
		}
	}
	if mapped != nil {
		return mapped, true, nil
	}
	return nil, false, errors.New("STUN response has no mapped address")
}

func parseSTUNAddress(value []byte, xor bool, tx [12]byte) (*net.UDPAddr, error) {
	if len(value) < 4 || value[0] != 0 {
		return nil, errors.New("invalid STUN address attribute")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return nil, errors.New("short STUN IPv4 address")
		}
		ip := append(net.IP(nil), value[4:8]...)
		if xor {
			var cookie [4]byte
			binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
			for i := range 4 {
				ip[i] ^= cookie[i]
			}
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02: // IPv6
		if len(value) < 20 {
			return nil, errors.New("short STUN IPv6 address")
		}
		ip := append(net.IP(nil), value[4:20]...)
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
			copy(mask[4:], tx[:])
			for i := range 16 {
				ip[i] ^= mask[i]
			}
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	default:
		return nil, errors.New("unsupported STUN address family")
	}
}
