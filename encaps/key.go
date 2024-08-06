package encaps

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
)

// Generate generates a new key pair.
func Generate(scheme kem.Scheme) (PublicKey, PrivateKey, error) {
	seed := crypto.Rand(scheme.SeedSize())
	return DeriveKey(scheme, seed)
}

// DeriveKey creates a new private and public key from the given scheme and seed.
// Panics if the scheme is nil.
func DeriveKey(scheme kem.Scheme, seed []byte) (PublicKey, PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	pub := &publicKey{
		PublicKey: pk,
	}

	priv := &privateKey{
		publicKey:  pub,
		PrivateKey: sk,
	}

	return pub, priv, nil
}

// Keys upgrades the given public and private keys.
// If the public key is nil, it will be given from the private key.
func Keys(pk kem.PublicKey, sk kem.PrivateKey) (PublicKey, PrivateKey) {
	if pk == nil {
		if sk == nil {
			return nil, nil
		}
		pk = sk.Public()
	}
	pub := &publicKey{PublicKey: pk}
	if sk == nil {
		return pub, nil
	}
	return pub, &privateKey{publicKey: pub, PrivateKey: sk}
}

// Pub upgrades the given public key.
func Pub(pk kem.PublicKey) PublicKey {
	pub, _ := Keys(pk, nil)
	return pub
}

// PublicKey represents a KEM public key.
type PublicKey interface {
	quark.KeyID
	Scheme() kem.Scheme
	Equal(PublicKey) bool

	// Pack allocates a new slice of bytes with Scheme().PublicKeySize() length
	// and writes the public key to it.
	Pack() []byte

	// Encapsulate encapsulates a shared secret derived from provided seed.
	Encapsulate(seed []byte) (ciphertext, secret []byte, err error)

	Raw() kem.PublicKey
}

// PrivateKey represents a KEM private key.
type PrivateKey interface {
	quark.KeyID
	Scheme() kem.Scheme
	Equal(PrivateKey) bool
	Public() PublicKey

	// Pack allocates a new slice of bytes with Scheme().PrivateKeySize() length
	// and writes the private key to it.
	Pack() []byte

	// Decapsulate decapsulates the shared secret from the provided ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)

	Raw() kem.PrivateKey
}

var _ PublicKey = (*publicKey)(nil)
var _ PrivateKey = (*privateKey)(nil)

type publicKey struct {
	kem.PublicKey
	fp quark.Fingerprint
	id quark.ID
}

func (p *publicKey) ID() quark.ID {
	if p.id.IsEmpty() {
		p.id = p.Fingerprint().ID()
	}
	return p.id
}

func (p *publicKey) Fingerprint() quark.Fingerprint {
	if p.fp.IsEmpty() {
		p.fp = quark.CalculateFingerprint(p.Scheme().Name(), p.Pack())
	}
	return p.fp
}

func (p publicKey) Equal(other PublicKey) bool {
	if other, ok := other.(*publicKey); ok {
		return p.PublicKey.Equal(other.PublicKey)
	}
	return false
}

func (p publicKey) Raw() kem.PublicKey {
	return p.PublicKey
}

type privateKey struct {
	kem.PrivateKey
	*publicKey
}

func (p privateKey) Equal(other PrivateKey) bool {
	if other, ok := other.(*privateKey); ok {
		return p.PrivateKey.Equal(other.PrivateKey)
	}
	return false
}

func (p *privateKey) Raw() kem.PrivateKey {
	return p.PrivateKey
}

func (p *privateKey) Public() PublicKey {
	return p.publicKey
}
