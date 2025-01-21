package internal

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/scheme"
)

// Cipher represents authenticated cipher.
type Cipher interface {
	Crypt(dst, src []byte)

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}

// NewFunc represents the function to create an AEAD cipher.
type NewFunc func(key, nonce, associatedData []byte) Cipher

// New creates new AEAD scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key and nonce lengths
// that are passed to the enc and dec functions.
func New(name string, keySize, nonceSize, tagSize int, enc, dec NewFunc) *Scheme {
	return &Scheme{
		String:    scheme.String(name),
		keySize:   keySize,
		nonceSize: nonceSize,
		tagSize:   tagSize,
		enc:       enc,
		dec:       dec,
	}
}

type Scheme struct {
	scheme.String
	keySize   int
	nonceSize int
	tagSize   int
	enc, dec  NewFunc
}

func (s *Scheme) KeySize() int   { return s.keySize }
func (s *Scheme) NonceSize() int { return s.nonceSize }
func (s *Scheme) TagSize() int   { return s.tagSize }

func (s *Scheme) Encrypt(key, nonce, associatedData []byte) Cipher {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	crypto.LenOrPanic(nonce, s.nonceSize, ErrNonceSize)
	return s.enc(key, nonce, associatedData)
}

func (s *Scheme) Decrypt(key, nonce, associatedData []byte) Cipher {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	crypto.LenOrPanic(nonce, s.nonceSize, ErrNonceSize)
	return s.dec(key, nonce, associatedData)
}

// errors.
var (
	ErrKeySize   = cipher.ErrKeySize
	ErrNonceSize = errors.New("invalid nonce size")
)
