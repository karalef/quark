package aead

import (
	"github.com/karalef/aead"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead/etm"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/scheme"
)

// NewFunc represents the function to create an AEAD cipher.
type NewFunc func(key, nonce, associatedData []byte) aead.Cipher

// New creates new AEAD scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key and nonce lengths
// that are passed to the newFunc.
func New(name string, keySize, nonceSize, tagSize int, newFunc NewFunc) Scheme {
	return sch{
		String:    scheme.String(name),
		keySize:   keySize,
		nonceSize: nonceSize,
		tagSize:   tagSize,
		newFunc:   newFunc,
	}
}

// NewEtM creates new AEAD scheme using EtM (Encrypt-then-MAC) construction.
func NewEtM(name string, cipher cipher.Scheme, mac mac.Scheme) Scheme {
	if cipher == nil || mac == nil {
		panic("nil scheme part")
	}
	return New(name, cipher.KeySize(), cipher.IVSize(), mac.Size(),
		func(key, nonce, associatedData []byte) aead.Cipher {
			return etm.New(cipher, mac, key, nonce, associatedData)
		})
}

type sch struct {
	scheme.String
	keySize   int
	nonceSize int
	tagSize   int
	newFunc   NewFunc
}

func (s sch) KeySize() int   { return s.keySize }
func (s sch) NonceSize() int { return s.nonceSize }
func (s sch) TagSize() int   { return s.tagSize }

func (s sch) Encrypt(key, nonce, associatedData []byte) aead.Stream {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	crypto.LenOrPanic(nonce, s.nonceSize, ErrNonceSize)
	return aead.Encrypter(s.newFunc(key, nonce, associatedData))
}

func (s sch) Decrypt(key, nonce, associatedData []byte) aead.Stream {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	crypto.LenOrPanic(nonce, s.nonceSize, ErrNonceSize)
	return aead.Decrypter(s.newFunc(key, nonce, associatedData))
}

// errors.
var (
	ErrKeySize   = aead.ErrKeySize
	ErrNonceSize = aead.ErrNonceSize
)
