package kdf

import (
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
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
	return New(name, func(secret, salt []byte) Expander {
		return xof.Extract(x, secret, salt)
	}, func(prk []byte) Expander {
		return xof.Extract(x, nil, prk)
	})
}

// NewHKDF creates a new Scheme from HMAC.
// It does not register the scheme.
func NewHKDF(name string, hmac mac.Scheme) Scheme {
	return New(name, func(secret, salt []byte) Expander {
		return mac.NewHKDF(hmac).Extract(salt, secret)
	}, func(prk []byte) Expander {
		return mac.NewExpander(hmac, prk)
	})
}

// schemes.
var (
	BLAKE3x  = NewXOF(xof.BLAKE3x.Name(), xof.BLAKE3x)
	SHAKE128 = NewXOF(xof.Shake128.Name(), xof.Shake128)
	SHAKE256 = NewXOF(xof.Shake256.Name(), xof.Shake256)

	HMAC_BLAKE3 = NewHKDF(mac.BLAKE3.Name(), mac.BLAKE3)
	HMAC_SHA256 = NewHKDF(mac.SHA256.Name(), mac.SHA256)
	HMAC_SHA3   = NewHKDF(mac.SHA3.Name(), mac.SHA3)
)
