package key

import (
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/single"
	"github.com/karalef/quark/pack"
)

// PacketTagPrivateKey is a private key packet tag.
const PacketTagPrivateKey = 0x02

func init() {
	pack.RegisterPacketType(pack.NewType((*Key)(nil), "private key", "PRIVATE KEY"))
}

var _ pack.Packable = (*Key)(nil)

// Encrypt encrypts a key with passphrase.
func Encrypt(key crypto.Key, passphrase string, nonce []byte, p encrypted.PassphraseParams) (*Key, error) {
	fp := key.Fingerprint()
	data, err := single.NewPassphraseData(passphrase, key.Pack(), nonce, fp.Bytes(), p)
	if err != nil {
		return nil, err
	}
	return &Key{
		Algorithm: strings.ToUpper(key.Scheme().Name()),
		FP:        fp,
		Data:      data,
	}, nil
}

// Key is used to store the private key encrypted with passphrase.
type Key struct {
	Algorithm string                `msgpack:"alg"`
	Data      single.PassphraseData `msgpack:"data"`
	FP        crypto.Fingerprint    `msgpack:"fp"`
}

func (*Key) PacketTag() pack.Tag { return PacketTagPrivateKey }

// Decrypt decrypts the key with passphrase.
func (k *Key) Decrypt(passphrase string) ([]byte, error) {
	return k.Data.Decrypt(passphrase, k.FP.Bytes(), true)
}

// Decrypt decrypts the sign key with the given passphrase.
func (k *Key) DecryptSign(passphrase string) (sign.PrivateKey, error) {
	material, err := k.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}
	return sign.UnpackPrivate(k.Algorithm, material)
}

// Decrypt decrypts the KEM key with the given passphrase.
func (k *Key) DecryptKEM(passphrase string) (kem.PrivateKey, error) {
	material, err := k.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}
	return kem.UnpackPrivate(k.Algorithm, material)
}
