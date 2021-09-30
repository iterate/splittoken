// Package splittoken provides a simple implementation of a three part token
// which is serialized to a string. They consist of an identifier, a secret part
// and a usage identifier.
//
// These tokens are heavily inspired by GitHub's new tokens,
// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/.
//
// A common use case for these token are whenever you need to issue something to
// a user that can be used as a proof of identity, for email verification, etc.
// You would usually want to store the secret part hashed in your own
// application to prevent anyone with database access to impersonate a user by
// reconstructing a token.
//
// This Paragon.ie post from 2017 describes this approach:
// https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels.
package splittoken

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/eknkc/basex"
	"github.com/google/uuid"
)

const stdEnc = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var enc = mustEnc(basex.NewEncoding(stdEnc))

var (
	ErrInvalidChecksum = errors.New("invalid checksum")
	ErrInvalidSyntax   = errors.New("invalid syntax")
)

// Token is a split token.
type Token string

func (t Token) Secret() []byte {
	p, err := parse(t)
	if err != nil {
		return nil
	}
	return p.secret
}

func (t Token) Serial() uuid.UUID {
	p, err := parse(t)
	if err != nil {
		return uuid.Nil
	}
	return p.serial
}
func (t Token) Usage() string {
	p, err := parse(t)
	if err != nil {
		return "nil"
	}
	return p.usage
}

func parse(t Token) (parts, error) {
	var res parts
	ps := strings.Split(string(t), "_")
	if len(ps) != 2 {
		return parts{}, ErrInvalidSyntax
	}
	res.usage = ps[0]

	bs, err := enc.Decode(ps[1])
	if err != nil {
		return res, ErrInvalidSyntax
	}

	// the token must be at least 16 + 1 + 4 = 21 bytes
	if len(bs) < 21 {
		return res, ErrInvalidSyntax
	}

	secretLen := len(bs) - 16 - 4
	res.secret = make([]byte, secretLen, secretLen)

	copy(res.serial[:], bs[0:16])
	copy(res.secret, bs[16:16+secretLen])

	checksum := bs[len(bs)-4:]
	wantSum := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(wantSum, crc32.ChecksumIEEE(bs[:len(bs)-4]))
	if subtle.ConstantTimeCompare(checksum, wantSum) != 1 {
		return res, ErrInvalidChecksum
	}

	return res, nil
}

// NewToken constructs a new token.
func New(usage string, serial uuid.UUID, secret []byte) (Token, error) {
	return encode(parts{
		usage:  usage,
		serial: serial,
		secret: secret,
	})
}

func Generate(usage string, bytes uint) (Token, error) {
	id := uuid.Must(uuid.NewRandom())
	secret := make([]byte, bytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("writing bytes: %v", err)
	}
	return New(usage, id, secret)
}

func encode(p parts) (Token, error) {
	if len(p.usage) < 1 {
		return "", ErrInvalidSyntax
	}
	if strings.Contains(p.usage, "_") {
		return "", ErrInvalidSyntax
	}
	if len(p.secret) < 1 {
		return "", ErrInvalidSyntax
	}
	bl := len(p.serial) + len(p.secret) + 4
	bs := make([]byte, bl, bl)
	copy(bs[:16], p.serial[:])
	copy(bs[16:], p.secret)

	binary.BigEndian.PutUint32(bs[len(bs)-4:], crc32.ChecksumIEEE(bs[:len(bs)-4]))
	return Token(fmt.Sprintf("%s_%s", p.usage, enc.Encode(bs))), nil
}

type parts struct {
	usage  string
	serial uuid.UUID
	secret []byte
}

func mustEnc(encoding *basex.Encoding, err error) *basex.Encoding {
	if err != nil {
		panic(err)
	}
	return encoding
}

func Verify(t Token) error {
	if _, err := parse(t); err != nil {
		return err
	}
	return nil
}
