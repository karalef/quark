package kem

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/keys/internal"
	"github.com/karalef/quark/pack"
)

const PacketTagEncryptedPrivateKeyKEM = 0x03

type Scheme = kem.Scheme

func ByName(name string) Scheme { return kem.ByName(name) }

type PublicKey struct {
	internal.PublicKey[kem.PublicKey, kem.Scheme]
}

// Encapsulate generates and encapsulates a shared secret.
func Encapsulate(recipient *PublicKey) (encapsed, secret []byte, err error) {
	return recipient.Encapsulate(crypto.Rand(recipient.Scheme().EncapsulationSeedSize()))
}

func (p *PublicKey) Encapsulate(seed []byte) (ciphertext, secret []byte, err error) {
	return p.Raw().Encapsulate(seed)
}

func (p *PublicKey) CorrespondsTo(sk *PrivateKey) bool {
	return sk.PrivateKey.Public() == &p.PublicKey || sk.Fingerprint() == p.Fingerprint()
}

type PrivateKey struct {
	internal.PrivateKey[kem.PrivateKey, kem.PublicKey, kem.Scheme]
}

func (p PrivateKey) Public() *PublicKey {
	return internal.UnsafeCast[PublicKey](p.PrivateKey.Public())
}

func (p PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return p.Raw().Decapsulate(ciphertext)
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

func (*Encrypted) PacketTag() pack.Tag { return PacketTagEncryptedPrivateKeyKEM }

// Scheme returns the scheme.
func (e Encrypted) Scheme() kem.Scheme {
	return kem.ByName(internal.Encrypted(e).Key.Algorithm)
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
