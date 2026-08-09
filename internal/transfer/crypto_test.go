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

func TestFourWordCodeAndOpaqueRoom(t *testing.T) {
	code, err := generateCodePhrase()
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeCodePhrase(code)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != code || len(strings.Split(code, "-")) != 4 {
		t.Fatalf("bad code %q", code)
	}
	room1, err := roomFromCodePhrase(code)
	if err != nil {
		t.Fatal(err)
	}
	room2, err := roomFromCodePhrase(strings.ToUpper(code))
	if err != nil {
		t.Fatal(err)
	}
	if room1 != room2 || !validOpaqueRoom(room1) {
		t.Fatalf("bad opaque room %q %q", room1, room2)
	}
	if strings.Contains(strings.ToLower(room1), strings.Split(code, "-")[0]) {
		t.Fatal("room leaked code word")
	}
}

func TestPAKESecretWrap(t *testing.T) {
	key, _ := generateTransferSecret()
	secret, _ := generateTransferSecret()
	blob, err := wrapTransferSecret(key, "ABCDEFGH23456789", strings.Repeat("a", 64), secret, []string{"192.168.1.7:41234"})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := unwrapTransferSecret(key, "ABCDEFGH23456789", strings.Repeat("a", 64), blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret wrap mismatch")
	}
	wrong, _ := generateTransferSecret()
	if _, _, err := unwrapTransferSecret(wrong, "ABCDEFGH23456789", strings.Repeat("a", 64), blob); err == nil {
		t.Fatal("wrong PAKE key opened envelope")
	}
}

func TestFourWordRoomDoesNotVerifyFullPAKESecret(t *testing.T) {
	base := "amberbird-amberbird-cloudstream-dreamrocket"
	// Low four bits of word #2 are intentionally hidden behind PAKE, so this
	// phrase must resolve to the same public rendezvous room while producing a
	// different PAKE passphrase.
	secretVariant := "amberbird-amberbrook-cloudstream-dreamrocket"
	roomA, err := roomFromCodePhrase(base)
	if err != nil {
		t.Fatal(err)
	}
	roomB, err := roomFromCodePhrase(secretVariant)
	if err != nil {
		t.Fatal(err)
	}
	if roomA != roomB {
		t.Fatalf("secret-only code variation changed public room: %s != %s", roomA, roomB)
	}
	passA, _ := pakePassphraseFromCodePhrase(base)
	passB, _ := pakePassphraseFromCodePhrase(secretVariant)
	if passA == passB {
		t.Fatal("secret-only code variation did not change PAKE passphrase")
	}

	// Crossing the 16-word routing bucket for word #2 must alter the room.
	routeVariant := "amberbird-amberkite-cloudstream-dreamrocket"
	roomC, err := roomFromCodePhrase(routeVariant)
	if err != nil {
		t.Fatal(err)
	}
	if roomC == roomA {
		t.Fatal("routing selector variation unexpectedly kept the same room")
	}
}
