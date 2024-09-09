package kem

import (
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/internal"
)

// Generate derives a key-pair from a seed generated by provided rand.
//
// If rand is nil, crypto/rand is used.
func Generate(s Scheme, rand io.Reader) (PrivateKey, PublicKey, error) {
	seed, err := crypto.RandRead(rand, s.SeedSize())
	if err != nil {
		return nil, nil, err
	}
	return s.DeriveKey(seed)
}

// Encapsulate is wrapper for PublicKey.Encapsulate with random seed.
func Encapsulate(p PublicKey) (ciphertext []byte, secret []byte, err error) {
	return p.Encapsulate(crypto.Rand(p.Scheme().(Scheme).EncapsulationSeedSize()))
}

// Scheme represents a KEM scheme.
type Scheme interface {
	crypto.Scheme

	// DeriveKey derives a key-pair from a seed.
	DeriveKey(seed []byte) (PrivateKey, PublicKey, error)

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (PublicKey, error)

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (PrivateKey, error)

	// Size of encapsulated shared secret.
	CiphertextSize() int

	// Size of shared secret.
	SharedSecretSize() int

	// Size of encapsulation seed.
	EncapsulationSeedSize() int
}

// PrivateKey represents a KEM private key.
type PrivateKey interface {
	crypto.Key
	Public() PublicKey
	Equal(PrivateKey) bool

	// Decapsulate decapsulates the shared secret from the provided ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a KEM public key.
type PublicKey interface {
	crypto.Key
	CorrespondsTo(PrivateKey) bool
	Equal(PublicKey) bool

	// Encapsulate encapsulates a shared secret generated from provided seed.
	Encapsulate(seed []byte) (ciphertext, secret []byte, err error)
}

// errors.
var (
	ErrKeySize           = errors.New("invalid key size")
	ErrSeedSize          = errors.New("invalid seed size")
	ErrCiphertext        = errors.New("invalid ciphertext size")
	ErrEncapsulationSeed = errors.New("invalid encapsulation seed size")
)

var schemes = make(internal.Schemes[Scheme])

// Register registers a KEM scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the KEM scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered KEM algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered KEM schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
