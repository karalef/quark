package crypto

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// Generate derives a key-pair from a seed generated using crypto/rand.
func Generate[Public, Private Key](scheme KeyScheme[Public, Private]) (Public, Private) {
	return scheme.DeriveKey(Rand(scheme.SeedSize()))
}

// Scheme represents a PKI scheme.
type Scheme interface {
	scheme.Scheme

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of seed.
	SeedSize() int

	// Size of algorithm output.
	Size() int
}

// PublicScheme represents the PKI scheme with method to unpack public keys.
type PublicScheme[Public Key] interface {
	Scheme

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (Public, error)
}

// PrivateScheme represents the PKI scheme with method to unpack private keys.
type PrivateScheme[Private Key] interface {
	Scheme

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (Private, error)
}

// KeyScheme represents the PKI scheme with methods to derive and unpack keys.
type KeyScheme[Public, Private Key] interface {
	PublicScheme[Public]
	PrivateScheme[Private]

	// DeriveKey derives a key-pair from a seed.
	// Panics if seed is not of SeedSize() length.
	DeriveKey(seed []byte) (Public, Private)
}

// Key represents a PKI key.
type Key interface {
	// Pack allocates a new slice of bytes with Scheme().{Private, Public}KeySize() length
	// and writes the key to it.
	Pack() []byte
}

// SchemeKey represents a key with a parametrized scheme.
type SchemeKey[S Scheme] interface {
	Key

	// Scheme returns the scheme.
	Scheme() S
}

// Public represents a public key.
type Public[Self Key] interface {
	Key

	// Equal checks if the key is equal to the provided key.
	Equal(Self) bool
}

// PublicKey represents a PKI public key.
type PublicKey[S Scheme, Self Key] interface {
	SchemeKey[S]

	// Equal checks if the key is equal to the provided key.
	Equal(Self) bool
}

// Private represents a private key.
type Private[Self, Pub Key] interface {
	Public[Self]

	// Public returns the public key.
	Public() Pub
}

// PrivateKey represents a PKI private key.
type PrivateKey[S Scheme, Self, Public Key] interface {
	PublicKey[S, Self]

	// Public returns the public key.
	Public() Public
}

// CorrespondsTo checks if the private key corresponds to the public key.
func CorrespondsTo[Sch Scheme, P PublicKey[Sch, P], S PrivateKey[Sch, S, P]](pk P, sk S) bool {
	return pk.Equal(sk.Public())
}

// ErrKeyNotCorrespond is returned when the key does not correspond to the private key.
var ErrKeyNotCorrespond = errors.New("key does not correspond to private key")
