package transfer

import (
	"crypto/rand"
	"testing"
)

func TestPakeP256AgreementAndConfirmation(t *testing.T) {
	room := "ABCDEFGH23456789"
	password := []byte("silvercastle-mangoriver-orbitrocket-velvettiger")
	idA, idB := pakeIdentities(room)
	a, err := initPakeP256(password, 0, idA, idB)
	if err != nil {
		t.Fatal(err)
	}
	aWire, _ := a.publicBytes()
	b, err := initPakeP256(password, 1, idA, idB)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.update(aWire); err != nil {
		t.Fatal(err)
	}
	bWire, _ := b.publicBytes()
	if err := a.update(bWire); err != nil {
		t.Fatal(err)
	}
	if string(a.key) != string(b.key) {
		t.Fatal("PAKE shared keys differ")
	}
	salt := make([]byte, pakeSaltSize)
	_, _ = rand.Read(salt)
	ak, err := derivePakeChannelKeys(a.key, room, aWire, bWire, salt)
	if err != nil {
		t.Fatal(err)
	}
	bk, err := derivePakeChannelKeys(b.key, room, aWire, bWire, salt)
	if err != nil {
		t.Fatal(err)
	}
	if string(ak.EncryptionKey) != string(bk.EncryptionKey) {
		t.Fatal("channel keys differ")
	}
	if !pakeConfirm(ak.ConfirmationA, bk.ConfirmationA) || !pakeConfirm(ak.ConfirmationB, bk.ConfirmationB) {
		t.Fatal("confirmation tags differ")
	}
}

func TestPakeWrongPasswordDoesNotConfirm(t *testing.T) {
	room := "ABCDEFGH23456789"
	idA, idB := pakeIdentities(room)
	a, _ := initPakeP256([]byte("amberbird-bluecastle-cloudriver-dreamrocket"), 0, idA, idB)
	aWire, _ := a.publicBytes()
	b, _ := initPakeP256([]byte("amberbird-bluecastle-cloudriver-dreamtiger"), 1, idA, idB)
	if err := b.update(aWire); err != nil {
		t.Fatal(err)
	}
	bWire, _ := b.publicBytes()
	if err := a.update(bWire); err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, pakeSaltSize)
	_, _ = rand.Read(salt)
	ak, _ := derivePakeChannelKeys(a.key, room, aWire, bWire, salt)
	bk, _ := derivePakeChannelKeys(b.key, room, aWire, bWire, salt)
	if pakeConfirm(ak.ConfirmationB, bk.ConfirmationB) {
		t.Fatal("wrong password unexpectedly confirmed")
	}
}
