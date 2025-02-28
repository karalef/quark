package kem

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem/internal"
)

// Generate derives a key-pair from a seed generated using crypto/rand.
func Generate(s Scheme) (PublicKey, PrivateKey) {
	return s.DeriveKey(crypto.Rand(s.SeedSize()))
}

// Encapsulate is wrapper for PublicKey.Encapsulate with random seed.
func Encapsulate(p PublicKey) (ciphertext []byte, secret []byte, err error) {
	return p.Encapsulate(crypto.Rand(p.Scheme().EncapsulationSeedSize()))
}

// Scheme represents a KEM scheme.
type Scheme = internal.Scheme

// PrivateKey represents a KEM private key.
type PrivateKey = internal.PrivateKey

// PublicKey represents a KEM public key.
type PublicKey = internal.PublicKey

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = internal.ErrKeySize

// ErrSeedSize is an error with which DeriveKey panics.
var ErrSeedSize = internal.ErrSeedSize

// ErrCiphertext is returned when the ciphertext size is invalid.
var ErrCiphertext = internal.ErrCiphertext

// ErrEncapsulationSeed is an error with which Encapsulate panics.
var ErrEncapsulationSeed = internal.ErrEncapsulationSeed
