package key

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/pack"
)

// PacketTagPrivateKey is a private key packet tag.
const PacketTagPrivateKey = 0x02

func init() {
	pack.RegisterPacketType(pack.NewType((*Key)(nil), "private key", "PRIVATE KEY"))
}

var _ pack.Packable = (*Key)(nil)

// Encrypt encrypts a key with passphrase.
func Encrypt(key crypto.Key, passphrase string, nonce []byte, p encrypted.Passphrase) (*Key, error) {
	enc, err := NewEncrypter(passphrase, encrypted.Nonce(nonce), p)
	if err != nil {
		return nil, err
	}
	data, err := enc.Encrypt(key)
	if err != nil {
		return nil, err
	}
	return &Key{Passphrase: p, Sub: data}, nil
}

// Key is used to store the private key encrypted with passphrase.
type Key struct {
	Passphrase encrypted.Passphrase `msgpack:"passphrase"`
	Sub        `msgpack:",inline"`
}

func (k Key) ID() crypto.ID                   { return k.Sub.FP.ID() }
func (k Key) Fingerprint() crypto.Fingerprint { return k.Sub.FP }

func (*Key) PacketTag() pack.Tag { return PacketTagPrivateKey }

// Decrypt decrypts the key with passphrase.
func (k *Key) Decrypt(passphrase string) ([]byte, error) {
	crypter, err := k.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	m, err := k.Sub.Decrypt(crypter)
	return m, err
}

// DecryptKey decrypts the key with the given passphrase.
func (k *Key) DecryptKey(passphrase string) (crypto.Key, error) {
	crypter, err := k.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	key, err := k.Sub.DecryptKey(crypter)
	return key, err
}

// Decrypt decrypts the sign key with the given passphrase.
func (k *Key) DecryptSign(passphrase string) (sign.PrivateKey, error) {
	crypter, err := k.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	key, err := k.Sub.DecryptSign(crypter)
	return key, err
}

// Decrypt decrypts the KEM key with the given passphrase.
func (k *Key) DecryptKEM(passphrase string) (kem.PrivateKey, error) {
	crypter, err := k.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	key, err := k.Sub.DecryptKEM(crypter)
	return key, err
}
