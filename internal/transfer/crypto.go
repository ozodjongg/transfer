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
	"errors"
	"io"
	"strings"
)

const (
	transferSecretSize = 32
	manifestAAD        = "pro-transfer/v5/manifest"
	dataAADPrefix      = "pro-transfer/v5/data"
)

func generateTransferSecret() ([]byte, error) {
	secret := make([]byte, transferSecretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func encodeTransferCode(room string, secret []byte) string {
	return strings.ToUpper(strings.TrimSpace(room)) + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func parseTransferCode(code string) (room string, secret []byte, err error) {
	code = strings.TrimSpace(code)
	parts := strings.Split(code, ".")
	if len(parts) != 2 {
		return "", nil, errors.New("transfer code noto'g'ri: ROOM.SECRET formatida bo'lishi kerak")
	}
	room = strings.ToUpper(strings.TrimSpace(parts[0]))
	if room == "" {
		return "", nil, errors.New("room code bo'sh")
	}
	secret, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil || len(secret) != transferSecretSize {
		return "", nil, errors.New("transfer secret noto'g'ri")
	}
	return room, secret, nil
}

func hkdfSHA256(secret []byte, info string, n int) []byte {
	salt := []byte("pro-transfer/v5/hkdf-salt")
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)

	out := make([]byte, 0, n)
	var previous []byte
	var counter byte = 1
	for len(out) < n {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write([]byte(info))
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		need := n - len(out)
		if need > len(previous) {
			need = len(previous)
		}
		out = append(out, previous[:need]...)
		counter++
	}
	return out
}

func newAEAD(secret []byte, label string) (cipher.AEAD, error) {
	key := hkdfSHA256(secret, label, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encryptManifest(secret, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(secret, "manifest-key")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(manifestAAD))
	return append(nonce, sealed...), nil
}

func decryptManifest(secret, blob []byte) ([]byte, error) {
	aead, err := newAEAD(secret, "manifest-key")
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("encrypted manifest juda qisqa")
	}
	nonce := blob[:aead.NonceSize()]
	ciphertext := blob[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(manifestAAD))
	if err != nil {
		return nil, errors.New("manifest decrypt/authentication failed")
	}
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
