package transfer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"example.com/pro-transfer/internal/protocol"
)

func senderPakeExchange(conn net.Conn, phrase, room, transferID string, transferSecret []byte, routes []string) error {
	first, err := protocol.ReadMessage(conn)
	if err != nil {
		return err
	}
	if first.Type == protocol.TypeError {
		return errors.New(first.Text)
	}
	if first.Type != protocol.TypePakeA || len(first.Payload) == 0 {
		return errors.New("PAKE initiator message expected")
	}
	passphrase, err := pakePassphraseFromCodePhrase(phrase)
	if err != nil {
		return err
	}
	idA, idB := pakeIdentities(room)
	p, err := initPakeP256([]byte(passphrase), 1, idA, idB)
	if err != nil {
		return err
	}
	if err := p.update(first.Payload); err != nil {
		return fmt.Errorf("PAKE sender update: %w", err)
	}
	responder, err := p.publicBytes()
	if err != nil {
		return err
	}
	shared := append([]byte(nil), p.key...)
	if len(shared) == 0 {
		return errors.New("PAKE sender session key missing")
	}
	salt := make([]byte, pakeSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	keys, err := derivePakeChannelKeys(shared, room, first.Payload, responder, salt)
	if err != nil {
		return err
	}
	if err := protocol.WriteMessage(conn, protocol.Message{
		Type: protocol.TypePakeB, Room: room, Payload: responder, Salt: salt, Confirm: keys.ConfirmationB,
	}); err != nil {
		return err
	}

	confirm, err := protocol.ReadMessage(conn)
	if err != nil {
		return err
	}
	if confirm.Type == protocol.TypeError {
		return errors.New(confirm.Text)
	}
	if confirm.Type != protocol.TypePakeConfirmA || !pakeConfirm(keys.ConfirmationA, confirm.Confirm) {
		return errors.New("PAKE receiver confirmation failed")
	}

	wrapped, err := wrapTransferSecret(keys.EncryptionKey, room, transferID, transferSecret, routes)
	if err != nil {
		return err
	}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypeSecretWrap, Room: room, Payload: wrapped}); err != nil {
		return err
	}
	ok, err := protocol.ReadMessage(conn)
	if err != nil {
		return err
	}
	if ok.Type == protocol.TypeError {
		return errors.New(ok.Text)
	}
	if ok.Type != protocol.TypePakeOK {
		return errors.New("PAKE receiver acknowledgement missing")
	}
	return nil
}

func receiverPakeExchange(conn net.Conn, phrase, room, transferID string) (secret []byte, routes []string, err error) {
	passphrase, err := pakePassphraseFromCodePhrase(phrase)
	if err != nil {
		return nil, nil, err
	}
	idA, idB := pakeIdentities(room)
	p, err := initPakeP256([]byte(passphrase), 0, idA, idB)
	if err != nil {
		return nil, nil, err
	}
	initiator, err := p.publicBytes()
	if err != nil {
		return nil, nil, err
	}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypePakeA, Room: room, Payload: initiator}); err != nil {
		return nil, nil, err
	}

	second, err := protocol.ReadMessage(conn)
	if err != nil {
		return nil, nil, err
	}
	if second.Type == protocol.TypeError {
		return nil, nil, errors.New(second.Text)
	}
	if second.Type != protocol.TypePakeB || len(second.Payload) == 0 || len(second.Salt) != pakeSaltSize {
		return nil, nil, errors.New("PAKE responder message invalid")
	}
	if err := p.update(second.Payload); err != nil {
		return nil, nil, fmt.Errorf("PAKE receiver update: %w", err)
	}
	shared := append([]byte(nil), p.key...)
	if len(shared) == 0 {
		return nil, nil, errors.New("PAKE receiver session key missing")
	}
	keys, err := derivePakeChannelKeys(shared, room, initiator, second.Payload, second.Salt)
	if err != nil {
		return nil, nil, err
	}
	if !pakeConfirm(keys.ConfirmationB, second.Confirm) {
		return nil, nil, errors.New("PAKE sender confirmation failed: transfer code noto'g'ri yoki peer almashtirilgan")
	}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypePakeConfirmA, Room: room, Confirm: keys.ConfirmationA}); err != nil {
		return nil, nil, err
	}

	wrapped, err := protocol.ReadMessage(conn)
	if err != nil {
		return nil, nil, err
	}
	if wrapped.Type == protocol.TypeError {
		return nil, nil, errors.New(wrapped.Text)
	}
	if wrapped.Type != protocol.TypeSecretWrap || len(wrapped.Payload) == 0 {
		return nil, nil, errors.New("PAKE transfer secret envelope expected")
	}
	secret, routes, err = unwrapTransferSecret(keys.EncryptionKey, room, transferID, wrapped.Payload)
	if err != nil {
		return nil, nil, err
	}
	if err := protocol.WriteMessage(conn, protocol.Message{Type: protocol.TypePakeOK, Room: room}); err != nil {
		return nil, nil, err
	}
	return secret, routes, nil
}
