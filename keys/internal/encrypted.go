package internal

import (
	"strings"

	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/keys"
)

// KeyParameters is a password encryption parameters for key encryption.
type KeyParameters struct {
	Passphrase string
	SaltSize   int
	Scheme     password.Scheme
	KDFParams  kdf.Params
}

// EncryptKey encrypts a key with passphrase.
func EncryptKey(scheme internal.Scheme, material []byte, fp keys.Fingerprint, p KeyParameters) (*Encrypted, error) {
	alg := strings.ToUpper(scheme.Name())
	cipher, sym, err := encrypted.PasswordEncrypt(p.Scheme, p.Passphrase, p.SaltSize, []byte(alg), p.KDFParams)
	if err != nil {
		return nil, err
	}
	cipher.Crypt(material, material)

	return &Encrypted{
		Key: keys.Model{
			Algorithm: alg,
			Key:       material,
		},
		FP:  fp,
		Sym: *sym,
		Tag: cipher.Tag(nil),
	}, nil
}

// Encrypted is used to store the private key encrypted with passphrase.
type Encrypted struct {
	Key keys.Model          `msgpack:"key"`
	FP  keys.Fingerprint    `msgpack:"fp"`
	Sym encrypted.Symmetric `msgpack:"sym"`
	Tag []byte              `msgpack:"tag"`
}

// Decrypt decrypts the key with passphrase.
func (k *Encrypted) Decrypt(passphrase string) ([]byte, error) {
	cipher, err := k.Sym.PasswordDecrypt(passphrase, []byte(k.Key.Algorithm))
	if err != nil {
		return nil, err
	}

	key := make([]byte, len(k.Key.Key))
	cipher.Crypt(key, k.Key.Key)
	if !mac.Equal(k.Tag, cipher.Tag(nil)) {
		return nil, mac.ErrMismatch
	}

	return key, nil
}
