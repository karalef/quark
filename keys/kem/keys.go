package kem

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/keys/internal"
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
	pub := Pub(pk)
	if sk == nil {
		return pub, nil
	}
	return Pub(pk), &PrivateKey{internal.NewPrivate(sk, &pub.PublicKey)}
}

// Pub upgrades the given public key.
func Pub(pk kem.PublicKey) *PublicKey {
	if pk == nil {
		return nil
	}
	return &PublicKey{internal.NewPublic(pk)}
}

// Priv upgrades the given private key.
func Priv(sk kem.PrivateKey) *PrivateKey {
	if sk == nil {
		return nil
	}
	return &PrivateKey{internal.NewPrivate(sk, nil)}
}
