package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version      = 7
	MaxFrameSize = 4 * 1024 * 1024

	TypeCreate        = "create"
	TypeJoin          = "join"
	TypeResumeSend    = "resume_send"
	TypeResumeReceive = "resume_receive"
	TypeCancel        = "cancel"
	TypeDataSend      = "data_send"
	TypeDataReceive   = "data_receive"

	TypePakeA        = "pake_a"
	TypePakeB        = "pake_b"
	TypePakeConfirmA = "pake_confirm_a"
	TypeSecretWrap   = "secret_wrap"
	TypePakeOK       = "pake_ok"

	TypeCreated       = "created"
	TypeJoined        = "joined"
	TypeReceiverReady = "receiver_ready"
	TypePeerReady     = "peer_ready"
	TypeVerified      = "verified"
	TypeComplete      = "complete"
	TypeError         = "error"
)

type Message struct {
	Version int          `json:"version"`
	Type    string       `json:"type"`
	Room    string       `json:"room,omitempty"`
	Text    string       `json:"text,omitempty"`
	Offset  int64        `json:"offset,omitempty"`  // single-stream encrypted payload offset
	Offsets []int64      `json:"offsets,omitempty"` // per-stream encrypted payload offsets
	Proof   string       `json:"proof,omitempty"`
	Token   string       `json:"token,omitempty"`
	Stream  int          `json:"stream,omitempty"`
	Session *SessionMeta `json:"session,omitempty"`
	Payload []byte       `json:"payload,omitempty"`
	Salt    []byte       `json:"salt,omitempty"`
	Confirm []byte       `json:"confirm,omitempty"`
}

// SessionMeta intentionally contains no filenames, folder names or plaintext
// hashes. Manifest is already end-to-end encrypted by the sender.
// ResumeRooms are opaque HMAC-derived aliases; knowing them does not reveal the
// transfer secret or manifest.
type SessionMeta struct {
	TransferID         string   `json:"transfer_id"`
	PlainSize          int64    `json:"plain_size"`
	PayloadSize        int64    `json:"payload_size"`
	EncryptedManifest  []byte   `json:"encrypted_manifest,omitempty"`
	ResumeRooms        []string `json:"resume_rooms,omitempty"`
	StreamCount        int      `json:"stream_count,omitempty"`
	StreamPayloadSizes []int64  `json:"stream_payload_sizes,omitempty"`
	AttachToken        string   `json:"attach_token,omitempty"`
}

func WriteMessage(w io.Writer, msg Message) error {
	msg.Version = Version
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("protocol frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func ReadMessage(r io.Reader) (Message, error) {
	var msg Message
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return msg, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrameSize {
		return msg, fmt.Errorf("invalid protocol frame size: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return msg, err
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return msg, fmt.Errorf("invalid protocol message: %w", err)
	}
	if msg.Version != Version {
		return msg, errors.New("unsupported protocol version")
	}
	return msg, nil
}
