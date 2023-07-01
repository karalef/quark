package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// Algorithm represents algorithm as string.
type Algorithm string

// InvalidAlgorithm represents unsupported or invalid algorithm.
const InvalidAlgorithm Algorithm = "INVALID"

const (
	schemeDelim = "::"
	schemeParts = 3 // CERT::SIGN::KEM
)

// ParseScheme parses string with format "CERT::SIGN::KEM".
func ParseScheme(s string) (Scheme, error) {
	parts := strings.Split(strings.ToUpper(s), schemeDelim)
	if len(parts) != schemeParts {
		return Scheme{}, ErrInvalidScheme
	}
	sch := Scheme{
		Cert: sign.ByName(parts[0]),
		Sign: sign.ByName(parts[1]),
		KEM:  kem.ByName(parts[2]),
	}
	if !sch.IsValid() {
		return Scheme{}, ErrInvalidScheme
	}
	return sch, nil
}

// ErrInvalidScheme is returned if at least one part of the scheme cannot be determined.
var ErrInvalidScheme = errors.New("invalid scheme")

var _ pack.CustomEncoder = Scheme{}
var _ pack.CustomDecoder = (*Scheme)(nil)

// Scheme type.
type Scheme struct {
	Cert sign.Scheme
	Sign sign.Scheme
	KEM  kem.Scheme
}

func (s Scheme) String() string {
	return strings.ToUpper(s.Cert.Name() +
		schemeDelim + s.Sign.Name() +
		schemeDelim + s.KEM.Name(),
	)
}

// IsValid returns true if scheme is valid.
func (s Scheme) IsValid() bool {
	return s.Cert != nil && s.Sign != nil && s.KEM != nil
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s Scheme) EncodeMsgpack(enc *pack.Encoder) error {
	if !s.IsValid() {
		return ErrInvalidScheme
	}
	return enc.EncodeString(s.String())
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *Scheme) DecodeMsgpack(dec *pack.Decoder) error {
	sch, err := dec.DecodeString()
	if err != nil {
		return err
	}

	ps, err := ParseScheme(sch)
	if err != nil {
		return err
	}
	*s = ps
	return nil
}
