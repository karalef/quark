package crypto

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// Scheme is a basic interface for asymmetric algorithm schemes.
type Scheme interface {
	scheme.Scheme

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of seed.
	SeedSize() int
}

// NewKeyID creates a new key ID from the given public key.
// It DOES NOT returns the pointer, but the KeyID requires to be a pointer
// or be inside a struct with pointer receiver.
func NewKeyID[PublicKey RawKey](k PublicKey) KeyID[PublicKey] {
	return KeyID[PublicKey]{PublicKey: k}
}

// KeyID is an extension of public key to support key ID.
type KeyID[PublicKey RawKey] struct {
	PublicKey PublicKey
	id        ID
	fp        Fingerprint
}

func (k KeyID[PublicKey]) Scheme() Scheme { return k.PublicKey.Scheme() }
func (k KeyID[PublicKey]) Pack() []byte   { return k.PublicKey.Pack() }

// ID returns the key ID.
func (k *KeyID[PublicKey]) ID() ID {
	if k.id.IsEmpty() {
		k.id = k.Fingerprint().ID()
	}
	return k.id
}

// Fingerprint returns the key fingerprint.
func (k *KeyID[PublicKey]) Fingerprint() Fingerprint {
	if k.fp.IsEmpty() {
		k.fp = CalculateFingerprint(k.PublicKey.Scheme().Name(), k.PublicKey.Pack())
	}
	return k.fp
}

// RawKey is a basic interface for asymmetric keys without key ID support.
type RawKey interface {
	// Scheme returns the scheme.
	Scheme() Scheme

	// Pack allocates a new slice of bytes with Scheme().{Private, Public}KeySize() length
	// and writes the key to it.
	Pack() []byte
}

// Key is a basic interface for asymmetric keys.
type Key interface {
	// ID returns the key ID.
	ID() ID

	// Fingerprint returns the key fingerprint.
	Fingerprint() Fingerprint

	RawKey
}

// Corresponds returns true if k1 and k2 have the same fingerprint.
func Corresponds(k1, k2 Key) bool {
	return k1.Fingerprint() == k2.Fingerprint()
}

// key errors.
var (
	ErrKeyNotCorrespond = errors.New("the public key does not correspond to the private key")
)
