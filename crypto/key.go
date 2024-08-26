package crypto

import (
	"errors"

	"github.com/karalef/quark/internal"
)

// Scheme is a basic interface for asymmetric algorithm schemes.
type Scheme interface {
	internal.Scheme

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of seed.
	SeedSize() int
}

// Key is a basic interface for asymmetric keys.
type Key[KeyScheme Scheme] interface {
	KeyID
	Scheme() KeyScheme

	// Pack allocates a new slice of bytes with Scheme().{Private, Public}KeySize() length
	// and writes the key to it.
	Pack() []byte
}

// Corresponds returns true if k1 and k2 have the same fingerprint.
func Corresponds[KeyScheme Scheme](k1, k2 Key[Scheme]) bool {
	return k1.Fingerprint().IsEqual(k2.Fingerprint())
}

// key errors.
var (
	ErrKeyNotCorrespond = errors.New("the public key does not correspond to the private key")
)
