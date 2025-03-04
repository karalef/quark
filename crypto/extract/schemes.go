package extract

import (
	"github.com/karalef/quark/crypto/kdf"
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

// NewKDF creates a new Scheme from KDF and extraction function.
// It does not register the scheme.
func NewKDF(name string, k kdf.Scheme, ext func(material, salt []byte) kdf.KDF) Scheme {
	return New(name, ext, k.New)
}

// NewXOF creates a new Scheme from XOF.
// It does not register the scheme.
func NewXOF(x xof.Scheme, k kdf.Scheme) Scheme {
	return NewKDF(x.Name(), k, func(material, salt []byte) kdf.KDF {
		return xof.Extract(x, material, salt)
	})
}

// NewHKDF creates a new Scheme from HMAC.
// It does not register the scheme.
func NewHKDF(hmac mac.Scheme, k kdf.Scheme) Scheme {
	return NewKDF(hmac.Name(), k, func(material, salt []byte) kdf.KDF {
		return k.New(mac.Extract(hmac, material, salt))
	})
}

// schemes.
var (
	BLAKE3x  = NewXOF(xof.BLAKE3x, kdf.BLAKE3x)
	SHAKE128 = NewXOF(xof.Shake128, kdf.SHAKE128)
	SHAKE256 = NewXOF(xof.Shake256, kdf.SHAKE256)

	HMAC_BLAKE3 = NewHKDF(mac.BLAKE3, kdf.HMAC_BLAKE3)
	HMAC_SHA256 = NewHKDF(mac.SHA256, kdf.HMAC_SHA256)
	HMAC_SHA3   = NewHKDF(mac.SHA3, kdf.HMAC_SHA3)
)
