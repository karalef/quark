package key

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/single"
	"github.com/karalef/quark/pack"
)

// packet tags.
const (
	PacketTagPrivateKey = 0x02
)

var (
	packetTypePrivateKey = pack.NewType((*Key)(nil), "private key", "PRIVATE KEY")
)

func init() {
	pack.RegisterPacketType(packetTypePrivateKey)
}

var _ pack.Packable = (*Key)(nil)

// Encrypt encrypts a key with passphrase.
func Encrypt(key crypto.Key, passphrase string, p encrypted.PassphraseParams) (*Key, error) {
	fp := key.Fingerprint()
	data, err := single.NewPassphraseData(passphrase, key.Pack(), fp.Bytes(), p)
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
	FP        crypto.Fingerprint    `msgpack:"fp"`
	Data      single.PassphraseData `msgpack:"data"`
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

	scheme := sign.ByName(k.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}

// Decrypt decrypts the KEM key with the given passphrase.
func (k *Key) DecryptKEM(passphrase string) (kem.PrivateKey, error) {
	material, err := k.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := kem.ByName(k.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}
