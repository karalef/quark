package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto/ae"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack"
)

// DefaultSymmetricScheme is the default symmetric encryption scheme.
var DefaultSymmetricScheme = SymmetricScheme{
	Scheme: ae.Build(ae.EncryptThanMAC, cipher.AESCTR128, mac.BLAKE2b128, xof.Shake128),
}

// Symmetric precedes the encrypted data and contains
// enough information to allow the receiver to begin decryption
// and calculation authentication tag.
type Symmetric struct {
	// encryption scheme
	Scheme SymmetricScheme `msgpack:"scheme"`

	// cipher iv
	IV []byte `msgpack:"iv"`
}

// AuthTag contains symmetric encryption authentication tag.
type AuthTag []byte

var _ pack.CustomEncoder = SymmetricScheme{}
var _ pack.CustomDecoder = (*SymmetricScheme)(nil)

// SymmetricScheme represents a symmetric encryption scheme.
type SymmetricScheme struct {
	ae.Scheme
}

func (s SymmetricScheme) String() string {
	return strings.ToUpper(s.Cipher().Name() +
		"-" + s.MAC().Name() +
		"-" + s.XOF().Name() +
		"-" + s.Approach().String())
}

var errInvalidSymmetricScheme = errors.New("invalid symmetric encryption scheme")

// ParseSymmetricScheme parses a symmetric encryption scheme.
func ParseSymmetricScheme(str string) (s SymmetricScheme, err error) {
	parts := strings.Split(str, "-")
	if len(parts) != 4 {
		return s, errInvalidSymmetricScheme
	}
	cipher := cipher.ByName(parts[0])
	mac := mac.ByName(parts[1])
	xof := xof.ByName(parts[2])
	approach := ae.ApproachFromString(parts[3])
	if cipher == nil || mac == nil || xof == nil || approach == ae.InvalidApproach {
		return s, errInvalidSymmetricScheme
	}
	s = SymmetricScheme{
		Scheme: ae.Build(approach, cipher, mac, xof),
	}
	return
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s SymmetricScheme) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.String())
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *SymmetricScheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	sch, err := ParseSymmetricScheme(str)
	if err != nil {
		return err
	}
	*s = sch
	return nil
}
