package transfer

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "io"
)

const (
    transferSecretSize = 32
    manifestAAD        = "pro-transfer/v7/manifest"
    dataAADPrefix      = "pro-transfer/v7/data"
    secretWrapAAD      = "pro-transfer/v7/pake-secret-wrap"
)

func deriveAttachToken(secret []byte) string {
    key := hkdfSHA256(secret, "public-data-attach-token", 32)
    return base64.RawURLEncoding.EncodeToString(key)
}

func generateTransferSecret() ([]byte, error) {
    secret := make([]byte, transferSecretSize)
    if _, err := io.ReadFull(rand.Reader, secret); err != nil {
        return nil, err
    }
    return secret, nil
}

// hkdfSHA256 is the V7 transfer-key schedule for the random 256-bit transfer
// secret delivered over PAKE.
func hkdfSHA256(secret []byte, info string, n int) []byte {
    return hkdfSHA256WithSalt(secret, []byte("pro-transfer/v7/hkdf-salt"), []byte(info), n)
}

func hkdfSHA256WithSalt(secret, salt, info []byte, n int) []byte {
    extract := hmac.New(sha256.New, salt)
    _, _ = extract.Write(secret)
    prk := extract.Sum(nil)

    out := make([]byte, 0, n)
    var previous []byte
    var counter byte = 1
    for len(out) < n {
        expand := hmac.New(sha256.New, prk)
        _, _ = expand.Write(previous)
        _, _ = expand.Write(info)
        _, _ = expand.Write([]byte{counter})
        previous = expand.Sum(nil)
        need := n - len(out)
        if need > len(previous) { need = len(previous) }
        out = append(out, previous[:need]...)
        counter++
    }
    return out
}

func newAEAD(secret []byte, label string) (cipher.AEAD, error) {
    key := hkdfSHA256(secret, label, 32)
    return newAEADFromKey(key)
}

func newAEADFromKey(key []byte) (cipher.AEAD, error) {
    if len(key) != 32 {
        return nil, errors.New("AES-256 key must be 32 bytes")
    }
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    return cipher.NewGCM(block)
}

func encryptManifest(secret, plaintext []byte) ([]byte, error) {
    aead, err := newAEAD(secret, "manifest-key")
    if err != nil { return nil, err }
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
    sealed := aead.Seal(nil, nonce, plaintext, []byte(manifestAAD))
    return append(nonce, sealed...), nil
}

func decryptManifest(secret, blob []byte) ([]byte, error) {
    aead, err := newAEAD(secret, "manifest-key")
    if err != nil { return nil, err }
    if len(blob) < aead.NonceSize()+aead.Overhead() {
        return nil, errors.New("encrypted manifest juda qisqa")
    }
    plain, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], []byte(manifestAAD))
    if err != nil { return nil, errors.New("manifest decrypt/authentication failed") }
    return plain, nil
}

func transferID(encryptedManifest []byte) string {
    sum := sha256.Sum256(encryptedManifest)
    return hex.EncodeToString(sum[:])
}

func chunkAAD(index uint64, plainSize int) []byte {
    b := make([]byte, len(dataAADPrefix)+8+4)
    copy(b, []byte(dataAADPrefix))
    binary.BigEndian.PutUint64(b[len(dataAADPrefix):], index)
    binary.BigEndian.PutUint32(b[len(dataAADPrefix)+8:], uint32(plainSize))
    return b
}

type transferSecretEnvelope struct {
    Secret []byte   `json:"secret"`
    Routes []string `json:"routes,omitempty"`
}

func wrapTransferSecret(pakeKey []byte, room, transferID string, secret []byte, routes []string) ([]byte, error) {
    if len(secret) != transferSecretSize {
        return nil, errors.New("transfer secret size invalid")
    }
    plain, err := json.Marshal(transferSecretEnvelope{Secret: secret, Routes: routes})
    if err != nil { return nil, err }
    aead, err := newAEADFromKey(pakeKey)
    if err != nil { return nil, err }
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
    aad := pakeFrame([]byte(secretWrapAAD), []byte(room), []byte(transferID))
    sealed := aead.Seal(nil, nonce, plain, aad)
    return append(nonce, sealed...), nil
}

func unwrapTransferSecret(pakeKey []byte, room, transferID string, blob []byte) ([]byte, []string, error) {
    aead, err := newAEADFromKey(pakeKey)
    if err != nil { return nil, nil, err }
    if len(blob) < aead.NonceSize()+aead.Overhead() {
        return nil, nil, errors.New("PAKE secret envelope juda qisqa")
    }
    aad := pakeFrame([]byte(secretWrapAAD), []byte(room), []byte(transferID))
    plain, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], aad)
    if err != nil { return nil, nil, errors.New("PAKE secret envelope authentication failed") }
    var env transferSecretEnvelope
    if err := json.Unmarshal(plain, &env); err != nil { return nil, nil, errors.New("PAKE secret envelope JSON buzilgan") }
    if len(env.Secret) != transferSecretSize { return nil, nil, errors.New("PAKE transfer secret noto'g'ri") }
    routes := sanitizeLANRouteCandidates(env.Routes)
    return append([]byte(nil), env.Secret...), routes, nil
}
