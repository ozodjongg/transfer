package transfer

import (
	"bytes"
	"strings"
	"testing"
)

func TestV6RouteHintEncryptedRoundTripAndTamper(t *testing.T) {
	secret, err := generateTransferSecret()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.10:41000", "10.0.0.5:41000"}
	blob, err := encryptRouteHint(secret, want)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, "192.168") || strings.Contains(blob, "10.0.0.5") {
		t.Fatal("route hint leaked plaintext address")
	}
	got, err := decryptRouteHint(secret, blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	bad := []byte(blob)
	bad[len(bad)-1] ^= 1
	if _, err := decryptRouteHint(secret, string(bad)); err == nil {
		t.Fatal("tampered route hint unexpectedly authenticated")
	}
}

func TestV6ResumeAliasesAndDirectProofAreSecretDerived(t *testing.T) {
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
			t.Fatal("different secret produced same alias at same index")
		}
		if seen[a[i]] {
			t.Fatal("duplicate alias")
		}
		seen[a[i]] = true
		if !validResumeAlias(a[i]) {
			t.Fatalf("invalid alias %q", a[i])
		}
	}
	proof := directProof(secret, "ROOM123456")
	if !verifyDirectProof(secret, "ROOM123456", proof) {
		t.Fatal("direct proof rejected")
	}
	if verifyDirectProof(other, "ROOM123456", proof) {
		t.Fatal("wrong secret accepted direct proof")
	}
	if verifyDirectProof(secret, "OTHERROOM1", proof) {
		t.Fatal("wrong room accepted direct proof")
	}
	if bytes.Equal(hkdfSHA256(secret, "public-data-attach-token", 32), hkdfSHA256(other, "public-data-attach-token", 32)) {
		t.Fatal("attach derivation collision")
	}
}
