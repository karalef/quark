package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/pack"
)

// Algorithm represents algorithm as string.
type Algorithm string

// InvalidAlgorithm represents unsupported or invalid algorithm.
const InvalidAlgorithm Algorithm = "INVALID"

const (
	schemeDelim = "::"
	schemeParts = 2
)

// ParseScheme parses string with format "SIGN::KEM".
func ParseScheme(s string) (Scheme, error) {
	parts := strings.Split(strings.ToUpper(s), schemeDelim)
	if len(parts) != schemeParts {
		return Scheme{}, ErrInvalidScheme
	}
	sch := Scheme{
		Sign: SignAlgorithm(parts[0]).Scheme(),
		KEM:  KEMAlgorithm(parts[1]).Scheme(),
	}
	if !sch.IsValid() {
		return Scheme{}, ErrInvalidScheme
	}
	return sch, nil
}

// scheme errors.
var (
	ErrInvalidScheme = errors.New("invalid scheme")
)

var _ pack.CustomEncoder = Scheme{}
var _ pack.CustomDecoder = (*Scheme)(nil)

// Scheme type.
type Scheme struct {
	Sign SignScheme
	KEM  KEMScheme
}

func (s Scheme) String() string {
	return strings.ToUpper(s.Sign.Alg().String() + schemeDelim +
		s.KEM.Alg().String())
}

// IsValid returns true if scheme is valid.
func (s Scheme) IsValid() bool {
	return s.Sign != nil && s.KEM != nil
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
