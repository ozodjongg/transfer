package transfer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	routeAAD           = "pro-transfer/v6/routes"
	directProofPrefix  = "pro-transfer/v6/direct-proof"
	maxRouteCandidates = 16
)

type routeHint struct {
	Candidates []string `json:"candidates"`
}

func localRouteCandidates(port int) []string {
	if port <= 0 || port > 65535 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			// V6 initially advertises private IPv4 and ULA/link-local IPv6.
			// Public addresses are deliberately excluded from the code hint.
			if v4 := ip.To4(); v4 != nil {
				if !isPrivateIPv4(v4) {
					continue
				}
				endpoint := net.JoinHostPort(v4.String(), fmt.Sprintf("%d", port))
				if _, ok := seen[endpoint]; !ok {
					seen[endpoint] = struct{}{}
					out = append(out, endpoint)
				}
				continue
			}
			if ip.To16() != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				endpoint := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
				if _, ok := seen[endpoint]; !ok {
					seen[endpoint] = struct{}{}
					out = append(out, endpoint)
				}
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxRouteCandidates {
		out = out[:maxRouteCandidates]
	}
	return out
}

func isPrivateIPv4(ip net.IP) bool {
	if len(ip) != net.IPv4len {
		return false
	}
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254)
}

func encryptRouteHint(secret []byte, candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", nil
	}
	plain, err := json.Marshal(routeHint{Candidates: candidates})
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(secret, "route-key")
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plain, []byte(routeAAD))
	blob := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

func decryptRouteHint(secret []byte, encoded string) ([]string, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	blob, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("LAN route hint noto'g'ri")
	}
	aead, err := newAEAD(secret, "route-key")
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("LAN route hint juda qisqa")
	}
	plain, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], []byte(routeAAD))
	if err != nil {
		return nil, errors.New("LAN route hint authentication failed")
	}
	var hint routeHint
	if err := json.Unmarshal(plain, &hint); err != nil {
		return nil, errors.New("LAN route hint JSON buzilgan")
	}
	if len(hint.Candidates) > maxRouteCandidates {
		return nil, errors.New("LAN route candidate limiti oshgan")
	}
	out := make([]string, 0, len(hint.Candidates))
	seen := map[string]struct{}{}
	for _, candidate := range hint.Candidates {
		candidate = strings.TrimSpace(candidate)
		host, port, err := net.SplitHostPort(candidate)
		if err != nil || host == "" || port == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}

func directProof(secret []byte, room string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(directProofPrefix))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strings.ToUpper(strings.TrimSpace(room))))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyDirectProof(secret []byte, room, proof string) bool {
	expected := directProof(secret, room)
	got, err1 := base64.RawURLEncoding.DecodeString(strings.TrimSpace(proof))
	want, err2 := base64.RawURLEncoding.DecodeString(expected)
	return err1 == nil && err2 == nil && hmac.Equal(got, want)
}

func deriveResumeRooms(secret []byte, count int) []string {
	if count <= 0 {
		return nil
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(fmt.Sprintf("pro-transfer/v6/resume-room/%d", i)))
		raw := mac.Sum(nil)
		code := enc.EncodeToString(raw[:10]) // 80-bit opaque alias
		if len(code) > 16 {
			code = code[:16]
		}
		out = append(out, code)
	}
	return out
}
