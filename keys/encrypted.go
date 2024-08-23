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
	PacketTagPrivateKeySign = 0x02
	PacketTagPrivateKeyKEM  = 0x03
)

var (
	packetTypePrivateKeySign = pack.NewType((*EncryptedSign)(nil), "sign private key", "SIGN PRIVATE KEY")
	packetTypePrivateKeyKEM  = pack.NewType((*EncryptedKEM)(nil), "KEM private key", "KEM PRIVATE KEY")
)

func init() {
	pack.RegisterPacketType(packetTypePrivateKeySign)
	pack.RegisterPacketType(packetTypePrivateKeyKEM)
}

// EncryptKEM encrypts the given KEM private key with the given parameters.
func EncryptKEM(sk kem.PrivateKey, passphrase string, p KeyParameters) (*EncryptedKEM, error) {
	ek, err := EncryptKey(sk, passphrase, p)
	return (*EncryptedKEM)(ek), err
}

// EncryptSign encrypts the given sign private key with the given parameters.
func EncryptSign(sk sign.PrivateKey, passphrase string, p KeyParameters) (*EncryptedSign, error) {
	ek, err := EncryptKey(sk, passphrase, p)
	return (*EncryptedSign)(ek), err
}

var _ pack.Packable = (*EncryptedKEM)(nil)
var _ pack.Packable = (*EncryptedSign)(nil)

type (
	// EncryptedSign is used to store the sign private key encrypted with passphrase.
	EncryptedSign Encrypted

	// EncryptedKEM is used to store the KEM private key encrypted with passphrase.
	EncryptedKEM Encrypted
)

func (*EncryptedSign) PacketTag() pack.Tag { return PacketTagPrivateKeySign }
func (*EncryptedKEM) PacketTag() pack.Tag  { return PacketTagPrivateKeyKEM }

func (e EncryptedSign) Scheme() sign.Scheme { return sign.ByName(Encrypted(e).Key.Algorithm) }
func (e EncryptedKEM) Scheme() kem.Scheme   { return kem.ByName(Encrypted(e).Key.Algorithm) }

// Decrypt decrypts the key with the given passphrase.
func (e *EncryptedSign) Decrypt(passphrase string) (sign.PrivateKey, error) {
	material, err := (*Encrypted)(e).Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := e.Scheme()
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}

// Decrypt decrypts the key with the given passphrase.
func (e *EncryptedKEM) Decrypt(passphrase string) (kem.PrivateKey, error) {
	material, err := (*Encrypted)(e).Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := e.Scheme()
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	return scheme.UnpackPrivate(material)
}

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
