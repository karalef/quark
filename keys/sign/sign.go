package sign

import (
	"errors"

	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/keys/internal"
	"github.com/karalef/quark/pack"
)

const PacketTagEncryptedPrivateKeySign = 0x02

type Scheme = sign.Scheme

func ByName(name string) Scheme { return sign.ByName(name) }

type PublicKey struct {
	internal.PublicKey[sign.PublicKey, sign.Scheme]
}

func (p *PublicKey) Verify(message, signature []byte) (bool, error) {
	return p.Raw().Verify(message, signature)
}

func (p *PublicKey) CorrespondsTo(sk *PrivateKey) bool {
	return sk.PrivateKey.Public() == &p.PublicKey || sk.Fingerprint() == p.Fingerprint()
}

type PrivateKey struct {
	internal.PrivateKey[sign.PrivateKey, sign.PublicKey, sign.Scheme]
}

func (p PrivateKey) Public() *PublicKey {
	return internal.UnsafeCast[PublicKey](p.PrivateKey.Public())
}

func (p PrivateKey) Sign(message []byte) []byte {
	return p.Raw().Sign(message)
}

type KeyParameters = internal.KeyParameters

// EncryptKey encrypts the given key with the given parameters.
func EncryptKey(sk *PrivateKey, p KeyParameters) (*Encrypted, error) {
	ek, err := internal.EncryptKey(sk.Scheme(), sk.Raw().Pack(), sk.Fingerprint(), p)
	return (*Encrypted)(ek), err
}

var _ pack.Packable = (*Encrypted)(nil)

// Encrypted is used to store the private key encrypted with passphrase.
type Encrypted internal.Encrypted

func (*Encrypted) PacketTag() pack.Tag { return PacketTagEncryptedPrivateKeySign }

// Scheme returns the scheme.
func (e Encrypted) Scheme() sign.Scheme {
	return sign.ByName(internal.Encrypted(e).Key.Algorithm)
}

// Decrypt decrypts the key with the given passphrase.
func (e *Encrypted) Decrypt(passphrase string) (*PrivateKey, error) {
	material, err := (*internal.Encrypted)(e).Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	scheme := e.Scheme()
	if scheme == nil {
		return nil, errors.New("unknown key algorithm")
	}
	priv, err := scheme.UnpackPrivate(material)
	if err != nil {
		return nil, err
	}
	return Priv(priv), nil
}
