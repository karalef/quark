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

// NewCipher is a function that creates a cipher.Cipher and mac.State.
type NewCipher = func(key, nonce, additionalData []byte) (cipher.Cipher, mac.State)

// BuildCustom creates a custom Encrypt-Than-MAC AEAD scheme.
func BuildCustom(name string, newCipher NewCipher, keySize, ivSize, macSize int) *internal.Scheme {
	if name == "" || newCipher == nil || keySize == 0 || ivSize == 0 || macSize == 0 {
		panic("nil scheme part")
	}
	return internal.New(name, keySize, ivSize, macSize,
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

// NewEncrypter creates a new aead encrypter using XORThenMAC.
func NewEncrypter(cipher cipher.Cipher, mac mac.State) internal.Cipher {
	return encrypter{
		cipher: cipher,
		State:  mac,
	}
}

// NewDecrypter creates a new aead decrypter using MACThenXOR.
func NewDecrypter(cipher cipher.Cipher, mac mac.State) internal.Cipher {
	return decrypter{
		cipher: cipher,
		State:  mac,
	}
}

type encrypter struct {
	cipher cipher.Cipher
	mac.State
}

type decrypter struct {
	cipher cipher.Cipher
	mac.State
}

func (e encrypter) Crypt(dst, src []byte) { XORThenMAC(e.cipher, e.State, dst, src) }
func (d decrypter) Crypt(dst, src []byte) { MACThenXOR(d.cipher, d.State, dst, src) }

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
