package kem

import (
	"errors"

	"github.com/karalef/quark/crypto"
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
type Scheme interface {
	crypto.KeyScheme[PublicKey, PrivateKey]

	// Size of encapsulated shared secret.
	Size() int

	// Size of shared secret.
	SharedSecretSize() int

	// Size of encapsulation seed.
	EncapsulationSeedSize() int
}

// PrivateKey represents a KEM private key.
type PrivateKey interface {
	crypto.PrivateKey[Scheme, PrivateKey, PublicKey]

	// Decapsulate decapsulates the shared secret from the provided ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a KEM public key.
type PublicKey interface {
	crypto.PublicKey[Scheme, PublicKey]

	// Encapsulate encapsulates a shared secret generated from provided seed.
	Encapsulate(seed []byte) (ciphertext, secret []byte, err error)
}

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

// ErrSeedSize is an error with which DeriveKey panics.
var ErrSeedSize = errors.New("invalid seed size")

// ErrCiphertext is returned when the ciphertext size is invalid.
var ErrCiphertext = errors.New("invalid ciphertext size")

// ErrEncapsulationSeed is an error with which Encapsulate panics.
var ErrEncapsulationSeed = errors.New("invalid encapsulation seed size")
