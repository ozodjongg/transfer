package transfer

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base32"
    "encoding/base64"
    "fmt"
    "net"
    "sort"
    "strconv"
    "strings"
)

const (
    directProofPrefix  = "pro-transfer/v7/direct-proof"
    maxRouteCandidates = 16
)

func localRouteCandidates(port int) []string {
    if port <= 0 || port > 65535 { return nil }
    seen := map[string]struct{}{}
    out := make([]string, 0, 8)
    ifaces, err := net.Interfaces()
    if err != nil { return nil }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 { continue }
        addrs, err := iface.Addrs()
        if err != nil { continue }
        for _, addr := range addrs {
            var ip net.IP
            switch a := addr.(type) {
            case *net.IPNet: ip = a.IP
            case *net.IPAddr: ip = a.IP
            }
            if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() { continue }
            if v4 := ip.To4(); v4 != nil {
                if !isPrivateIPv4(v4) { continue }
                ep := net.JoinHostPort(v4.String(), strconv.Itoa(port))
                if _, ok := seen[ep]; !ok { seen[ep] = struct{}{}; out = append(out, ep) }
                continue
            }
            if ip.To16() != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
                ep := net.JoinHostPort(ip.String(), strconv.Itoa(port))
                if _, ok := seen[ep]; !ok { seen[ep] = struct{}{}; out = append(out, ep) }
            }
        }
    }
    sort.Strings(out)
    if len(out) > maxRouteCandidates { out = out[:maxRouteCandidates] }
    return out
}

func isPrivateIPv4(ip net.IP) bool {
    v := ip.To4()
    if v == nil { return false }
    return v[0] == 10 || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) || (v[0] == 192 && v[1] == 168) || (v[0] == 169 && v[1] == 254)
}

// sanitizeLANRouteCandidates prevents a malicious sender from using the
// receiver as a generic TCP scanner. Only private/link-local addresses that
// belong to one of the receiver's own directly attached subnets are tried.
func sanitizeLANRouteCandidates(in []string) []string {
    if len(in) > maxRouteCandidates { in = in[:maxRouteCandidates] }
    seen := map[string]struct{}{}
    out := make([]string, 0, len(in))
    for _, candidate := range in {
        candidate = strings.TrimSpace(candidate)
        host, port, err := net.SplitHostPort(candidate)
        if err != nil { continue }
        p, err := strconv.Atoi(port)
        if err != nil || p <= 0 || p > 65535 { continue }
        ip := net.ParseIP(strings.Trim(host, "[]"))
        if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() { continue }
        if v4 := ip.To4(); v4 != nil {
            if !isPrivateIPv4(v4) || !ipOnLocalSubnet(v4) { continue }
        } else {
            if !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) || !ipOnLocalSubnet(ip) { continue }
        }
        ep := net.JoinHostPort(ip.String(), strconv.Itoa(p))
        if _, ok := seen[ep]; ok { continue }
        seen[ep] = struct{}{}
        out = append(out, ep)
    }
    sort.Strings(out)
    return out
}

func ipOnLocalSubnet(candidate net.IP) bool {
    ifaces, err := net.Interfaces()
    if err != nil { return false }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 { continue }
        addrs, err := iface.Addrs()
        if err != nil { continue }
        for _, addr := range addrs {
            ipnet, ok := addr.(*net.IPNet)
            if !ok || ipnet.IP == nil { continue }
            if (candidate.To4() != nil) != (ipnet.IP.To4() != nil) { continue }
            if ipnet.Contains(candidate) { return true }
        }
    }
    return false
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
    if count <= 0 { return nil }
    enc := base32.StdEncoding.WithPadding(base32.NoPadding)
    out := make([]string, 0, count)
    for i := 0; i < count; i++ {
        mac := hmac.New(sha256.New, secret)
        _, _ = mac.Write([]byte(fmt.Sprintf("pro-transfer/v7/resume-room/%d", i)))
        raw := mac.Sum(nil)
        code := enc.EncodeToString(raw[:10])
        if len(code) > 16 { code = code[:16] }
        out = append(out, code)
    }
    return out
}
