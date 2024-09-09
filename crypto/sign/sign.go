package sign

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

// Scheme represents signature scheme.
type Scheme interface {
	crypto.Scheme

	// DeriveKey derives a key-pair from a seed.
	DeriveKey(seed []byte) (PrivateKey, PublicKey, error)

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (PublicKey, error)

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (PrivateKey, error)

	// Size of signatures.
	SignatureSize() int
}

// PrivateKey represents a signing private key.
type PrivateKey interface {
	crypto.Key
	Public() PublicKey
	Equal(PrivateKey) bool

	Sign([]byte) []byte
}

// PublicKey represents a signing public key.
type PublicKey interface {
	crypto.Key
	CorrespondsTo(PrivateKey) bool
	Equal(PublicKey) bool

	Verify(message, signature []byte) (bool, error)
}

// errors.
var (
	ErrSignature = errors.New("invalid signature")
	ErrSeedSize  = errors.New("invalid seed size")
	ErrKeySize   = errors.New("invalid key size")
)

var schemes = make(internal.Schemes[Scheme])

// Register registers a signature scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the signature scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered signature algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered signature schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
