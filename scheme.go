package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

const (
	schemeDelim = "::"

	// kem, sign, hash
	schemeParts = 3
)

// ParseScheme parses string with format "KEM::SIGN::HASH".
func ParseScheme(s string) (Scheme, error) {
	parts := strings.Split(strings.ToUpper(s), schemeDelim)
	if len(parts) != schemeParts {
		return Scheme{}, ErrInvalidScheme
	}
	sch := Scheme{
		KEM:  kem.Algorithm(parts[0]).Scheme(),
		Sign: sign.Algorithm(parts[1]).Scheme(),
		Hash: hash.Algorithm(parts[2]).Scheme(),
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
	KEM  kem.Scheme
	Sign sign.Scheme
	Hash hash.Scheme
}

func (s Scheme) String() string {
	return strings.ToUpper(s.KEM.Alg().String() + schemeDelim +
		s.Sign.Alg().String() + schemeDelim +
		s.Hash.Alg().String())
}

// IsValid returns true if scheme is valid.
func (s Scheme) IsValid() bool {
	return s.KEM != nil && s.Sign != nil && s.Hash != nil
}
