package encaps

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
)

// Generate generates a new key pair.
func Generate(scheme kem.Scheme) (*PublicKey, *PrivateKey, error) {
	seed := crypto.Rand(scheme.SeedSize())
	return DeriveKey(scheme, seed)
}

// DeriveKey creates a new private and public key from the given scheme and seed.
// Panics if the scheme is nil.
func DeriveKey(scheme kem.Scheme, seed []byte) (*PublicKey, *PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	pub, priv := Keys(pk, sk)
	return pub, priv, nil
}

// Keys upgrades the given public and private keys.
// If the public key is nil, it will be given from the private key.
func Keys(pk kem.PublicKey, sk kem.PrivateKey) (*PublicKey, *PrivateKey) {
	if pk == nil {
		if sk == nil {
			return nil, nil
		}
		pk = sk.Public()
	}
	pub := &PublicKey{pk: pk}
	if sk == nil {
		return pub, nil
	}
	return pub, &PrivateKey{pk: pub, sk: sk}
}

// Pub upgrades the given public key.
func Pub(pk kem.PublicKey) *PublicKey {
	pub, _ := Keys(pk, nil)
	return pub
}

type PublicKey struct {
	pk kem.PublicKey
	fp quark.Fingerprint
	id quark.ID
}

func (p PublicKey) Scheme() kem.Scheme { return p.pk.Scheme() }
func (p PublicKey) Raw() kem.PublicKey { return p.pk }

func (p *PublicKey) Encapsulate(seed []byte) (ciphertext, secret []byte, err error) {
	return p.pk.Encapsulate(seed)
}

func (p *PublicKey) ID() quark.ID {
	if p.id.IsEmpty() {
		p.id = p.Fingerprint().ID()
	}
	return p.id
}

func (p *PublicKey) Fingerprint() quark.Fingerprint {
	if p.fp.IsEmpty() {
		p.fp = quark.CalculateFingerprint(p.Scheme().Name(), p.Raw().Pack())
	}
	return p.fp
}

type PrivateKey struct {
	sk kem.PrivateKey
	pk *PublicKey
}

func (p PrivateKey) ID() quark.ID                   { return p.pk.ID() }
func (p PrivateKey) Fingerprint() quark.Fingerprint { return p.pk.Fingerprint() }
func (p PrivateKey) Scheme() kem.Scheme             { return p.sk.Scheme() }
func (p PrivateKey) Public() *PublicKey             { return p.pk }
func (p PrivateKey) Raw() kem.PrivateKey            { return p.sk }

func (p PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return p.sk.Decapsulate(ciphertext)
}
