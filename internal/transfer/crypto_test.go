package transfer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptedManifestRoundTripAndHidesNames(t *testing.T) {
	secret, err := generateTransferSecret()
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Version: manifestVersion, ChunkSize: defaultChunkSize, TotalSize: 3, Entries: []ManifestEntry{{Path: "secret-folder/report.xlsx", Type: "file", Size: 3, SHA256: strings.Repeat("a", 64)}}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryptManifest(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("report.xlsx")) || bytes.Contains(enc, []byte("secret-folder")) {
		t.Fatal("encrypted manifest leaked plaintext names")
	}
	dec, err := decryptManifest(secret, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, dec) {
		t.Fatal("manifest roundtrip mismatch")
	}

	wrong, _ := generateTransferSecret()
	if _, err := decryptManifest(wrong, enc); err == nil {
		t.Fatal("wrong secret unexpectedly decrypted manifest")
	}
}

func TestTransferCodeRoundTrip(t *testing.T) {
	secret, _ := generateTransferSecret()
	code := encodeTransferCode("abc123", secret, "")
	room, got, _, err := parseTransferCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if room != "ABC123" || !bytes.Equal(got, secret) {
		t.Fatal("transfer code roundtrip mismatch")
	}
}
