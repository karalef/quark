package internal

import (
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/keys"
)

// RawPublicKey is an interface for public keys.
type RawPublicKey[Scheme internal.Scheme] interface {
	Pack() []byte
	Scheme() Scheme
}

func NewPublic[T RawPublicKey[Scheme], Scheme internal.Scheme](key T) PublicKey[T, Scheme] {
	return PublicKey[T, Scheme]{key: key}
}

// PublicKey is a public key with ID and fingerprint.
type PublicKey[T RawPublicKey[Scheme], Scheme internal.Scheme] struct {
	key T
	id  keys.ID
	fp  keys.Fingerprint
}

// Raw returns the raw public key.
func (k PublicKey[T, Scheme]) Raw() T { return k.key }

// Scheme returns the key scheme.
func (k PublicKey[T, Scheme]) Scheme() Scheme { return k.key.Scheme() }

// ID returns the key ID.
func (k PublicKey[T, Scheme]) ID() keys.ID {
	if k.id.IsEmpty() {
		k.id = k.Fingerprint().ID()
	}
	return k.id
}

// Fingerprint returns the key fingerprint.
func (k PublicKey[T, Scheme]) Fingerprint() keys.Fingerprint {
	if k.fp.IsEmpty() {
		k.fp = keys.CalculateFingerprint(k.key.Scheme().Name(), k.key.Pack())
	}
	return k.fp
}
