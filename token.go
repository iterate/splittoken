package splittoken

import (
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
	ErrInvalidSyntax = errors.New("invalid syntax")
)

// Token contains three pieces:
// - A usage identifier
// - A known serial number
// - A secret value
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
func NewToken(usage string, serial uuid.UUID, secret []byte) (Token, error) {
	return encode(parts{
		usage:  usage,
		serial: serial,
		secret: secret,
	})
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
	bs := make([]byte,  bl, bl)
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