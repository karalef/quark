package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/pack"
)

var _ pack.Packable = (*PrivateKey[crypto.Key])(nil)

// EncryptKey encrypts a private key with passphrase.
// If nonce is nil, a random nonce will be generated.
func EncryptKey[T crypto.Key](key T, passphrase string, nonce []byte, p encrypted.Passphrased) (*PrivateKey[T], error) {
	src := encrypted.NonceSource(encrypted.Nonce(nonce))
	if nonce == nil {
		src = encrypted.NewRandomNonce(p.NonceSize(), nil)
	}
	enc, err := encrypted.NewKeyEncrypter[T](passphrase, src, p)
	if err != nil {
		return nil, err
	}
	data, err := enc.Encrypt(key)
	if err != nil {
		return nil, err
	}
	return &PrivateKey[T]{Passphrase: p, Key: data}, nil
}

// PrivateKey is used to store the private key encrypted with passphrase.
type PrivateKey[T crypto.Key] struct {
	Passphrase       encrypted.Passphrased `msgpack:"passphrase"`
	encrypted.Key[T] `msgpack:",inline"`
}

// PacketTag implements pack.Packable interface.
func (*PrivateKey[_]) PacketTag() pack.Tag { return PacketTagPrivateKey }

// ID returns the key ID.
func (k PrivateKey[_]) ID() crypto.ID { return k.Key.FP.ID() }

// Fingerprint returns the key fingerprint.
func (k PrivateKey[_]) Fingerprint() crypto.Fingerprint { return k.Key.FP }

// DecryptMaterial decrypts the key material with passphrase.
func (k *PrivateKey[_]) DecryptMaterial(passphrase string) ([]byte, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return k.Key.DecryptMaterial(crypter)
}

// Decrypt decrypts the key with the given passphrase.
func (k *PrivateKey[T]) Decrypt(passphrase string) (T, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		var empty T
		return empty, err
	}
	return k.Key.Decrypt(crypter)
}

// DecryptKey decrypts the key with the given passphrase.
func (k *PrivateKey[_]) DecryptKey(passphrase string) (crypto.Key, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return k.Key.DecryptKey(crypter)
}

// DecryptSign decrypts the sign key with the given passphrase.
func (k *PrivateKey[_]) DecryptSign(passphrase string) (sign.PrivateKey, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return k.Key.DecryptSign(crypter)
}

// DecryptKEM decrypts the KEM key with the given passphrase.
func (k *PrivateKey[_]) DecryptKEM(passphrase string) (kem.PrivateKey, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return k.Key.DecryptKEM(crypter)
}

// DecryptPKE decrypts the PKE key with the given passphrase.
func (k *PrivateKey[_]) DecryptPKE(passphrase string) (pke.PrivateKey, error) {
	crypter, err := k.Passphrase.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return k.Key.DecryptPKE(crypter)
}
