package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/cipher"
	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

const (
	schemeDelim = "::"

	// kem, cipher, sign, hash
	schemeParts = 4
)

// ParseScheme parses string with format "KEM_CIPHER_SIGN_HASH".
func ParseScheme(s string) (Scheme, error) {
	parts := strings.Split(strings.ToUpper(s), schemeDelim)
	if len(parts) != schemeParts {
		return Scheme{}, ErrInvalidScheme
	}
	sch := Scheme{
		KEM:    kem.Algorithm(parts[0]).Scheme(),
		Cipher: cipher.Algorithm(parts[1]).Scheme(),
		Sign:   sign.Algorithm(parts[2]).Scheme(),
		Hash:   hash.Algorithm(parts[3]).Scheme(),
	}
	if !sch.IsValid() {
		return Scheme{}, ErrInvalidScheme
	}
	return sch, nil
}

var ErrInvalidScheme = errors.New("invalid scheme")

type Scheme struct {
	KEM    kem.Scheme
	Cipher cipher.Scheme
	Sign   sign.Scheme
	Hash   hash.Scheme
}

func (s Scheme) String() string {
	return strings.ToUpper(s.KEM.Alg().String() + schemeDelim +
		s.Cipher.Alg().String() + schemeDelim +
		s.Sign.Alg().String() + schemeDelim +
		s.Hash.Alg().String())
}

func (s Scheme) IsValid() bool {
	if !(s.KEM != nil && s.Cipher != nil &&
		s.Sign != nil && s.Hash != nil) {
		return false
	}
	return validateKEMSet(s.KEM, s.Cipher)
}
