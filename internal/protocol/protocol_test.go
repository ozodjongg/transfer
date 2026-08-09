package protocol

import (
	"bytes"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	want := Message{
		Type:   TypePeerReady,
		Room:   "ROOM123",
		Offset: 1024,
		Session: &SessionMeta{
			TransferID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PlainSize:         42,
			PayloadSize:       58,
			EncryptedManifest: []byte("ciphertext-only"),
		},
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Room != want.Room || got.Offset != want.Offset || got.Session == nil || got.Session.TransferID != want.Session.TransferID || !bytes.Equal(got.Session.EncryptedManifest, want.Session.EncryptedManifest) {
		t.Fatalf("unexpected round trip: %#v", got)
	}
}
