package kdf

import (
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(BLAKE3x)
	Register(SHAKE128)
	Register(SHAKE256)
	Register(HMAC_BLAKE3)
	Register(HMAC_SHA256)
	Register(HMAC_SHA3)
}

// NewXOF creates a new Scheme from XOF.
// It does not register the scheme.
func NewXOF(name string, x xof.Scheme) Scheme {
	return New(name, func(in []byte) KDF {
		return expander{xof.Extract(x, in, nil)}
	})
}

// NewHKDF creates a new Scheme from HMAC.
// It does not register the scheme.
func NewHKDF(name string, hmac mac.Scheme) Scheme {
	return hkdf{scheme.String(name), hmac}
}

type hkdf struct {
	scheme.String
	hmac mac.Scheme
}

func (h hkdf) New(prk []byte) KDF {
	if len(prk) < MinSize {
		panic(ErrShort)
	}
	return expander{mac.NewExpander(h.hmac, prk)}
}

type expander struct {
	exp interface {
		Expand(info []byte, l uint) []byte
	}
}

func (e expander) Derive(info []byte, length uint) []byte { return e.exp.Expand(info, length) }

// schemes.
var (
	BLAKE3x  = NewXOF(xof.BLAKE3x.Name(), xof.BLAKE3x)
	SHAKE128 = NewXOF(xof.Shake128.Name(), xof.Shake128)
	SHAKE256 = NewXOF(xof.Shake256.Name(), xof.Shake256)

	HMAC_BLAKE3 = NewHKDF(mac.BLAKE3.Name(), mac.BLAKE3)
	HMAC_SHA256 = NewHKDF(mac.SHA256.Name(), mac.SHA256)
	HMAC_SHA3   = NewHKDF(mac.SHA3.Name(), mac.SHA3)
)
