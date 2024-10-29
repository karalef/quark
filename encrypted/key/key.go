package key

import (
	"strings"

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
func Encrypt(key crypto.Key, passphrase string, nonce []byte, p encrypted.PassphraseParams) (*Key, error) {
	pass := encrypted.NewPassphrase(p)
	crypter, err := pass.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), nonce, fp.Bytes())
	if err != nil {
		return nil, err
	}
	return &Key{
		Algorithm:  strings.ToUpper(key.Scheme().Name()),
		FP:         fp,
		Passphrase: pass,
		Data:       data,
	}, nil
}

// Key is used to store the private key encrypted with passphrase.
type Key struct {
	Algorithm  string               `msgpack:"alg"`
	Passphrase encrypted.Passphrase `msgpack:"passphrase"`
	Data       encrypted.Data       `msgpack:"data"`
	FP         crypto.Fingerprint   `msgpack:"fp"`
}

func (*Key) PacketTag() pack.Tag { return PacketTagPrivateKey }

// Decrypt decrypts the key with passphrase.
func (k *Key) Decrypt(passphrase string) ([]byte, error) {
	crypter, err := k.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return crypter.DecryptDataBuf(k.Data, k.FP.Bytes())
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
