package keys

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/pack"
)

// packet tags.
const (
	PacketTagPrivateKey = 0x02
)

var (
	packetTypePrivateKey = pack.NewType((*Encrypted)(nil), "private key", "PRIVATE KEY")
)

func init() {
	pack.RegisterPacketType(packetTypePrivateKey)
}

var _ pack.Packable = (*Encrypted)(nil)

// KeyParameters is a password encryption parameters for key encryption.
type KeyParameters struct {
	SaltSize  int
	Scheme    password.Scheme
	KDFParams kdf.Params
}

// EncryptKey encrypts a key with passphrase.
func EncryptKey[Scheme crypto.Scheme](key crypto.Key[Scheme], passphrase string, p KeyParameters) (*Encrypted, error) {
	alg := strings.ToUpper(key.Scheme().Name())
	fp := key.Fingerprint()
	cipher, sym, err := encrypted.PasswordEncrypt(p.Scheme, passphrase, p.SaltSize, fp.Bytes(), p.KDFParams)
	if err != nil {
		return nil, err
	}
	material := key.Pack()
	cipher.Crypt(material, material)

	return &Encrypted{
		Key: Model{Algorithm: alg, Key: material},
		FP:  key.Fingerprint(),
		Sym: *sym,
		Tag: cipher.Tag(nil),
	}, nil
}

// Encrypted is used to store the private key encrypted with passphrase.
type Encrypted struct {
	Key Model               `msgpack:"key"`
	FP  crypto.Fingerprint  `msgpack:"fp"`
	Sym encrypted.Symmetric `msgpack:"sym"`
	Tag []byte              `msgpack:"tag"`
}

func (*Encrypted) PacketTag() pack.Tag { return PacketTagPrivateKey }

// Decrypt decrypts the key with passphrase.
func (k *Encrypted) Decrypt(passphrase string) ([]byte, error) {
	cipher, err := k.Sym.PasswordDecrypt(passphrase, k.FP.Bytes())
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

// Decrypt decrypts the sign key with the given passphrase.
func (k *Encrypted) DecryptSign(passphrase string) (sign.PrivateKey, error) {
	material, err := k.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := sign.ByName(k.Key.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}

// Decrypt decrypts the KEM key with the given passphrase.
func (k *Encrypted) DecryptKEM(passphrase string) (kem.PrivateKey, error) {
	material, err := k.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := kem.ByName(k.Key.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}
