package etm

import (
	"github.com/karalef/quark/crypto/aead/internal"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/hmac"
)

// New creates a new cipher. Panics if it is impossible to derive a MAC key or
// MAC key size is less than MinMACKeySize.
func New(ciph cipher.Scheme, m hmac.Scheme, key, nonce, ad []byte) internal.Cipher {
	bs := ciph.BlockSize()
	if m.KeySize() > bs {
		// impossible to derive a MAC key larger than the cipher block size
		panic(errMacKeySize)
	}

	size := min(bs, max(m.MaxKeySize(), m.KeySize()))

	return NewWithKeySize(ciph, m, key, nonce, ad, uint(size))
}

// NewWithKeySize creates a new cipher. Panics if size is invalid.
func NewWithKeySize(ciph cipher.Scheme, m hmac.Scheme, key, nonce, ad []byte, size uint) internal.Cipher {
	bs := uint(ciph.BlockSize())
	if size < MinMACKeySize || size > bs {
		panic(errMacKeySize)
	}
	cipher := ciph.New(key, nonce)
	mac := NewMAC(m, DeriveMACKeyFast(cipher, size, bs), ad)
	return crypter{cipher, mac}
}

type crypter struct {
	cipher cipher.Cipher
	hash.State
}

func (c crypter) Encrypt(dst, src []byte) { XORThenMAC(c.cipher, c.State, dst, src) }
func (c crypter) Decrypt(dst, src []byte) { MACThenXOR(c.cipher, c.State, dst, src) }
func (c crypter) TagSize() int            { return c.State.Size() }
func (c crypter) Tag(dst []byte) []byte   { return c.State.Sum(dst) }

//nolint:errcheck
func XORThenMAC(cipher cipher.Cipher, mac hash.State, dst, src []byte) {
	cipher.XORKeyStream(dst, src)
	mac.Write(dst[:len(src)])
}

//nolint:errcheck
func MACThenXOR(cipher cipher.Cipher, mac hash.State, dst, src []byte) {
	mac.Write(src)
	cipher.XORKeyStream(dst, src)
}
