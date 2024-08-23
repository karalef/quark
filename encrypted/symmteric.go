package encrypted

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/secret"
)

// Symmetric precedes the encrypted data and contains enough information to
// allow the receiver to begin decryption and calculation authentication tag.
type Symmetric struct {
	Password *Password `msgpack:"password,omitempty"`
	XOF      *XOF      `msgpack:"xof,omitempty"`

	IV     []byte `msgpack:"iv"`
	Scheme Scheme `msgpack:"scheme"`
}

// Encrypt creates a new AEAD cipher using shared secret.
// It automatically appends the scheme to the additional data.
func Encrypt(scheme secret.Scheme, sharedSecret, ad []byte) (aead.Cipher, *Symmetric, error) {
	if scheme == nil || sharedSecret == nil {
		return nil, nil, ErrInvalidParameters
	}

	iv := crypto.Rand(scheme.AEAD().Cipher().IVSize())
	ad = append(ad[:len(ad):len(ad)], []byte(strings.ToUpper(scheme.Name()))...)

	aead, err := scheme.Encrypter(iv, sharedSecret, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Symmetric{
		XOF:    &XOF{scheme.XOF()},
		IV:     iv,
		Scheme: Scheme{scheme.AEAD()},
	}, nil
}

// PasswordEncrypt creates a new AEAD cipher using passphrase.
// It automatically appends the scheme to the additional data.
func PasswordEncrypt(scheme password.Scheme, passphrase string, saltSize int, ad []byte, params kdf.Params) (aead.Cipher, *Symmetric, error) {
	if scheme == nil || passphrase == "" || params == nil {
		return nil, nil, ErrInvalidParameters
	}
	if saltSize < 16 {
		saltSize = 32
	}

	iv := crypto.Rand(scheme.AEAD().Cipher().IVSize())
	salt := crypto.Rand(saltSize)

	ad = append(ad[:len(ad):len(ad)], []byte(strings.ToUpper(scheme.Name()))...)

	aead, err := scheme.Encrypter(passphrase, iv, salt, ad, params)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Symmetric{
		Password: &Password{
			KDF:    scheme.KDF(),
			Params: params,
			Salt:   salt,
		},
		IV:     iv,
		Scheme: Scheme{scheme.AEAD()},
	}, nil
}

// Decrypt creates a new AEAD cipher using shared secret.
// It automatically appends the scheme to the additional data.
func (s Symmetric) Decrypt(sharedSecret, ad []byte) (aead.Cipher, error) {
	scheme := secret.Build(s.Scheme, s.XOF.XOF)
	ad = append(ad[:len(ad):len(ad)], []byte(strings.ToUpper(scheme.Name()))...)
	return scheme.Decrypter(s.IV, sharedSecret, ad)
}

// PasswordDecrypt creates a new AEAD cipher using passphrase.
// It automatically appends the scheme to the additional data.
func (s Symmetric) PasswordDecrypt(passphrase string, ad []byte) (aead.Cipher, error) {
	scheme := password.Build(s.Scheme, s.Password.KDF)
	ad = append(ad[:len(ad):len(ad)], []byte(strings.ToUpper(scheme.Name()))...)
	return scheme.Decrypter(passphrase, s.IV, s.Password.Salt, ad, s.Password.Params)
}

var (
	ErrInvalidParameters = errors.New("invalid parameters")
	ErrInvalidScheme     = errors.New("invalid symmetric encryption scheme")
)
