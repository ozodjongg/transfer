package transfer

// This file contains a narrowly scoped P-256 password-authenticated key
// agreement implementation adapted from github.com/schollz/pake/v3 v3.2.0
// (MIT License). Only the P-256 path needed by Pro Transfer V7 is retained.
// See THIRD_PARTY_NOTICES.md.

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

const (
	pakeProtocolVersion  = 1
	pakeCurveName        = "p256"
	pakeSaltSize         = 32
	pakePurposeTransfer  = "peer-transfer"
	pakeIdentityDomain   = "pro-transfer/v7/pake/participant/v1"
	pakeTranscriptDomain = "pro-transfer/v7/pake/channel/v1"
)

type pakeWire struct {
	Role int      `json:"role"`
	Ux   *big.Int `json:"ux,omitempty"`
	Uy   *big.Int `json:"uy,omitempty"`
	Vx   *big.Int `json:"vx,omitempty"`
	Vy   *big.Int `json:"vy,omitempty"`
	Xx   *big.Int `json:"xx,omitempty"`
	Xy   *big.Int `json:"xy,omitempty"`
	Yx   *big.Int `json:"yx,omitempty"`
	Yy   *big.Int `json:"yy,omitempty"`
}

type pakeP256 struct {
	// Public wire fields.
	Role   int
	Ux, Uy *big.Int
	Vx, Vy *big.Int
	Xx, Xy *big.Int
	Yx, Yy *big.Int

	// Private state.
	curve      elliptic.Curve
	fieldP     *big.Int
	password   []byte
	vPwX, vPwY *big.Int
	uPwX, uPwY *big.Int
	alpha      []byte
	zX, zY     *big.Int
	key        []byte
	idA, idB   []byte
}

func initPakeP256(password []byte, role int, idA, idB []byte) (*pakeP256, error) {
	if role != 0 && role != 1 {
		return nil, errors.New("PAKE role must be 0 or 1")
	}
	if len(password) == 0 || len(idA) == 0 || len(idB) == 0 {
		return nil, errors.New("PAKE password and identities are required")
	}
	curve := elliptic.P256()
	ux, _ := new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
	uy, _ := new(big.Int).SetString("59748757929350367369315811184980635230185250460108398961713395032485227207304", 10)
	vx, _ := new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
	vy, _ := new(big.Int).SetString("9157340230202296554417312816309453883742349874205386245733062928888341584123", 10)
	if !curve.IsOnCurve(ux, uy) || !curve.IsOnCurve(vx, vy) {
		return nil, errors.New("PAKE fixed point validation failed")
	}
	p := &pakeP256{
		Role: role, Ux: ux, Uy: uy, Vx: vx, Vy: vy,
		curve: curve, fieldP: curve.Params().P,
		password: append([]byte(nil), password...),
		idA:      append([]byte(nil), idA...), idB: append([]byte(nil), idB...),
	}
	if role == 0 {
		p.vPwX, p.vPwY = curve.ScalarMult(vx, vy, p.password)
		p.uPwX, p.uPwY = curve.ScalarMult(ux, uy, p.password)
		p.alpha = make([]byte, 32)
		if _, err := rand.Read(p.alpha); err != nil {
			return nil, err
		}
		ax, ay := curve.ScalarBaseMult(p.alpha)
		p.Xx, p.Xy = curve.Add(p.uPwX, p.uPwY, ax, ay)
	}
	return p, nil
}

func (p *pakeP256) publicBytes() ([]byte, error) {
	if p == nil {
		return nil, errors.New("PAKE not initialized")
	}
	return json.Marshal(pakeWire{
		Role: p.Role,
		Ux:   p.Ux, Uy: p.Uy,
		Vx: p.Vx, Vy: p.Vy,
		Xx: p.Xx, Xy: p.Xy,
		Yx: p.Yx, Yy: p.Yy,
	})
}

func (p *pakeP256) update(peerBytes []byte) error {
	if p == nil {
		return errors.New("PAKE not initialized")
	}
	var q pakeWire
	if err := json.Unmarshal(peerBytes, &q); err != nil {
		return fmt.Errorf("decode PAKE peer: %w", err)
	}
	if q.Role == p.Role {
		return errors.New("PAKE peer has same role")
	}
	if p.Role == 1 {
		if q.Xx == nil || q.Xy == nil || !p.curve.IsOnCurve(q.Xx, q.Xy) {
			return errors.New("invalid PAKE initiator point")
		}
		p.Xx, p.Xy = q.Xx, q.Xy
		p.vPwX, p.vPwY = p.curve.ScalarMult(p.Vx, p.Vy, p.password)
		p.uPwX, p.uPwY = p.curve.ScalarMult(p.Ux, p.Uy, p.password)
		p.alpha = make([]byte, 32)
		if _, err := rand.Read(p.alpha); err != nil {
			return err
		}
		ax, ay := p.curve.ScalarBaseMult(p.alpha)
		p.Yx, p.Yy = p.curve.Add(p.vPwX, p.vPwY, ax, ay)
		negY := new(big.Int).Neg(p.uPwY)
		negY.Mod(negY, p.fieldP)
		zx, zy := p.curve.Add(p.Xx, p.Xy, p.uPwX, negY)
		p.zX, p.zY = p.curve.ScalarMult(zx, zy, p.alpha)
	} else {
		if q.Yx == nil || q.Yy == nil || !p.curve.IsOnCurve(q.Yx, q.Yy) {
			return errors.New("invalid PAKE responder point")
		}
		p.Yx, p.Yy = q.Yx, q.Yy
		negY := new(big.Int).Neg(p.vPwY)
		negY.Mod(negY, p.fieldP)
		zx, zy := p.curve.Add(p.Yx, p.Yy, p.vPwX, negY)
		p.zX, p.zY = p.curve.ScalarMult(zx, zy, p.alpha)
	}
	p.key = p.deriveSessionKey()
	return nil
}

func (p *pakeP256) deriveSessionKey() []byte {
	h := sha256.New()
	writePakeField(h, []byte("pro-transfer/v7/pake/identity-bound-session-key/v1"))
	writePakeField(h, p.password)
	writePakeField(h, p.idA)
	writePakeField(h, p.idB)
	writePakeField(h, []byte(pakeCurveName))
	writePakeField(h, p.Xx.Bytes())
	writePakeField(h, p.Xy.Bytes())
	writePakeField(h, p.Yx.Bytes())
	writePakeField(h, p.Yy.Bytes())
	writePakeField(h, p.zX.Bytes())
	writePakeField(h, p.zY.Bytes())
	return h.Sum(nil)
}

func writePakeField(h hash.Hash, v []byte) {
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(v)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(v)
}

func pakeIdentities(room string) (idA, idB []byte) {
	version := make([]byte, 8)
	binary.LittleEndian.PutUint64(version, pakeProtocolVersion)
	idA = pakeFrame([]byte(pakeIdentityDomain), version, []byte(pakePurposeTransfer), []byte(room), []byte("receiver"))
	idB = pakeFrame([]byte(pakeIdentityDomain), version, []byte(pakePurposeTransfer), []byte(room), []byte("sender"))
	return
}

type pakeChannelKeys struct {
	EncryptionKey []byte
	ConfirmationA []byte
	ConfirmationB []byte
}

func derivePakeChannelKeys(shared []byte, room string, initiator, responder, salt []byte) (pakeChannelKeys, error) {
	if len(shared) == 0 || len(initiator) == 0 || len(responder) == 0 || len(salt) != pakeSaltSize {
		return pakeChannelKeys{}, errors.New("invalid PAKE transcript")
	}
	idA, idB := pakeIdentities(room)
	version := make([]byte, 8)
	binary.LittleEndian.PutUint64(version, pakeProtocolVersion)
	transcript := pakeFrame(
		[]byte(pakeTranscriptDomain), version, []byte(pakePurposeTransfer), []byte(room), []byte(pakeCurveName),
		idA, idB, initiator, responder, salt,
	)
	material := hkdfSHA256WithSalt(shared, salt, transcript, 96)
	enc := append([]byte(nil), material[:32]...)
	aKey := material[32:64]
	bKey := material[64:96]
	return pakeChannelKeys{
		EncryptionKey: enc,
		ConfirmationA: pakeConfirmTag(aKey, transcript),
		ConfirmationB: pakeConfirmTag(bKey, transcript),
	}, nil
}

func pakeConfirmTag(key, transcript []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(transcript)
	return mac.Sum(nil)
}

func pakeConfirm(expected, received []byte) bool {
	return len(expected) == sha256.Size && hmac.Equal(expected, received)
}

func pakeFrame(fields ...[]byte) []byte {
	total := 0
	for _, f := range fields {
		total += 8 + len(f)
	}
	out := make([]byte, 0, total)
	var n [8]byte
	for _, f := range fields {
		binary.LittleEndian.PutUint64(n[:], uint64(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}
