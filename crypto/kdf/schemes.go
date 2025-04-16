package kdf

import (
	"github.com/karalef/quark/crypto/hmac"
	"github.com/karalef/quark/crypto/xof"
)

func init() {
	Schemes.Register(BLAKE3x)
	Schemes.Register(SHAKE128)
	Schemes.Register(SHAKE256)
	Schemes.Register(HKDF_BLAKE3)
	Schemes.Register(HKDF_SHA256)
	Schemes.Register(HKDF_SHA3)
}

// NewXOF creates a new Scheme from XOF.
// It does not register the scheme.
func NewXOF(name string, x xof.Scheme) Scheme {
	return New(name, func(ikm, salt []byte) KDF {
		return xof.NewKDF(x, ikm, salt)
	})
}

// NewHKDF creates a new Scheme from HMAC.
// It does not register the scheme.
func NewHKDF(name string, scheme hmac.Scheme) Scheme {
	return New(name, func(ikm, salt []byte) KDF {
		return hmac.NewKDF(scheme, ikm, salt)
	})
}

// schemes.
var (
	BLAKE3x  = NewXOF(xof.BLAKE3x.Name(), xof.BLAKE3x)
	SHAKE128 = NewXOF(xof.Shake128.Name(), xof.Shake128)
	SHAKE256 = NewXOF(xof.Shake256.Name(), xof.Shake256)

	HKDF_BLAKE3 = NewHKDF("HKDF_BLAKE3", hmac.BLAKE3)
	HKDF_SHA256 = NewHKDF("HKDF_SHA256", hmac.SHA256)
	HKDF_SHA3   = NewHKDF("HKDF_SHA3", hmac.SHA3)
)
