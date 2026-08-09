package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version      = 2
	MaxFrameSize = 64 * 1024

	TypeCreate        = "create"
	TypeJoin          = "join"
	TypeResumeSend    = "resume_send"
	TypeResumeReceive = "resume_receive"
	TypeCreated       = "created"
	TypeJoined        = "joined"
	TypeReceiverReady = "receiver_ready"
	TypePeerReady     = "peer_ready"
	TypeVerified      = "verified"
	TypeComplete      = "complete"
	TypeError         = "error"
)

type Message struct {
	Version int       `json:"version"`
	Type    string    `json:"type"`
	Room    string    `json:"room,omitempty"`
	Text    string    `json:"text,omitempty"`
	Offset  int64     `json:"offset,omitempty"`
	File    *FileMeta `json:"file,omitempty"`
}

type FileMeta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
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
