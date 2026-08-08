package protocol

import (
	"bytes"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	want := Message{Type: TypeFileMeta, Room: "ROOM123", File: &FileMeta{Name: "a.xlsx", Size: 42, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Room != want.Room || got.File == nil || got.File.Name != want.File.Name || got.File.Size != want.File.Size {
		t.Fatalf("unexpected round trip: %#v", got)
	}
}
