package transfer

import (
	"bytes"
	"testing"
)

func TestV7ResumeAliasesAndDirectProofAreSecretDerived(t *testing.T) {
	secret, _ := generateTransferSecret()
	other, _ := generateTransferSecret()
	a := deriveResumeRooms(secret, 8)
	b := deriveResumeRooms(secret, 8)
	c := deriveResumeRooms(other, 8)
	if len(a) != 8 || len(b) != 8 || len(c) != 8 {
		t.Fatal("wrong alias count")
	}
	seen := map[string]bool{}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("same secret produced different aliases")
		}
		if a[i] == c[i] {
			t.Fatal("different secret produced same alias")
		}
		if seen[a[i]] {
			t.Fatal("duplicate alias")
		}
		seen[a[i]] = true
		if !validResumeAlias(a[i]) {
			t.Fatalf("invalid alias %q", a[i])
		}
	}
	room := "ABCDEFGH23456789"
	proof := directProof(secret, room)
	if !verifyDirectProof(secret, room, proof) {
		t.Fatal("direct proof rejected")
	}
	if verifyDirectProof(other, room, proof) {
		t.Fatal("wrong secret accepted direct proof")
	}
	if bytes.Equal(hkdfSHA256(secret, "public-data-attach-token", 32), hkdfSHA256(other, "public-data-attach-token", 32)) {
		t.Fatal("attach derivation collision")
	}
}
