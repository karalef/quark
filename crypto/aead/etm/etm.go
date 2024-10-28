package etm

import (
	"github.com/karalef/quark/crypto/aead/internal"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
)

// Build creates an AEAD scheme.
// Panics if one of the arguments is nil.
func Build(name string, cipher cipher.Scheme, mac mac.Scheme) *internal.Scheme {
	if cipher == nil || mac == nil {
		panic("nil scheme part")
	}
	if mac.KeySize() == 0 {
		panic("mac key size must be fixed")
	}
	bs, err := CheckMACKeySize(cipher, uint(mac.KeySize()))
	if err != nil {
		panic(err)
	}
	return internal.New(name, cipher.KeySize(), cipher.IVSize(), mac.Size(),
		func(key, nonce, associatedData []byte) internal.Cipher {
			return NewEncrypter(newCipher(cipher, bs, mac, key, nonce, associatedData))
		},
		func(key, nonce, associatedData []byte) internal.Cipher {
			return NewDecrypter(newCipher(cipher, bs, mac, key, nonce, associatedData))
		})
}

type NewCipher func(key, nonce, additionalData []byte) (cipher.Cipher, mac.State)

// BuildCustom creates an AEAD scheme with custom cipher creation.
// Schemes are used only to fill sizes.
func BuildCustom(name string, cipher cipher.Scheme, mac mac.Scheme, newCipher NewCipher) *internal.Scheme {
	if cipher == nil || mac == nil || newCipher == nil {
		panic("nil scheme part")
	}
	return internal.New(name, cipher.KeySize(), cipher.IVSize(), mac.Size(),
		func(key, nonce, associatedData []byte) internal.Cipher {
			return NewEncrypter(newCipher(key, nonce, associatedData))
		},
		func(key, nonce, associatedData []byte) internal.Cipher {
			return NewDecrypter(newCipher(key, nonce, associatedData))
		})
}

func newCipher(s cipher.Scheme, bs uint, m mac.Scheme, key, nonce, additionalData []byte) (cipher.Cipher, mac.State) {
	cipher, macKey := deriveMACKeyFast(s, key, nonce, uint(m.KeySize()), bs)
	return cipher, NewMAC(m, macKey, additionalData)
}

func NewEncrypter(cipher cipher.Cipher, mac mac.State) internal.Cipher {
	return crypter{
		cipher: cipher,
		mac:    mac,
		crypt:  XORThenMAC,
	}
}

func NewDecrypter(cipher cipher.Cipher, mac mac.State) internal.Cipher {
	return crypter{
		cipher: cipher,
		mac:    mac,
		crypt:  MACThenXOR,
	}
}

type crypter struct {
	cipher cipher.Cipher
	mac    mac.State
	crypt  func(cipher.Cipher, mac.State, []byte, []byte)
}

func (c crypter) Crypt(dst, src []byte) { c.crypt(c.cipher, c.mac, dst, src) }
func (c crypter) Tag(b []byte) []byte   { return c.mac.Tag(b) }

//nolint:errcheck
func XORThenMAC(cipher cipher.Cipher, mac mac.State, dst, src []byte) {
	cipher.XORKeyStream(dst, src)
	mac.Write(dst[:len(src)])
}

//nolint:errcheck
func MACThenXOR(cipher cipher.Cipher, mac mac.State, dst, src []byte) {
	mac.Write(src)
	cipher.XORKeyStream(dst, src)
}
