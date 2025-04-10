package kdf

import (
	"github.com/karalef/quark/crypto/mac"
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
func NewHKDF(name string, hmac mac.Scheme) Scheme {
	return New(name, func(ikm, salt []byte) KDF {
		return mac.NewKDF(hmac, ikm, salt)
	})
}

// schemes.
var (
	BLAKE3x  = NewXOF(xof.BLAKE3x.Name(), xof.BLAKE3x)
	SHAKE128 = NewXOF(xof.Shake128.Name(), xof.Shake128)
	SHAKE256 = NewXOF(xof.Shake256.Name(), xof.Shake256)

	HKDF_BLAKE3 = NewHKDF("HKDF_BLAKE3", mac.BLAKE3)
	HKDF_SHA256 = NewHKDF("HKDF_SHA256", mac.SHA256)
	HKDF_SHA3   = NewHKDF("HKDF_SHA3", mac.SHA3)
)
