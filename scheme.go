package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

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
		Sign: sign.Algorithm(parts[0]).Scheme(),
		KEM:  kem.Algorithm(parts[1]).Scheme(),
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

// Scheme type.
type Scheme struct {
	Sign sign.Scheme
	KEM  kem.Scheme
}

func (s Scheme) String() string {
	return strings.ToUpper(s.Sign.Alg().String() + schemeDelim +
		s.KEM.Alg().String())
}

// IsValid returns true if scheme is valid.
func (s Scheme) IsValid() bool {
	return s.Sign != nil && s.KEM != nil
}
