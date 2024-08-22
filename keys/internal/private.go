package internal

import (
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/keys"
)

// RawPublicKey is an interface for public keys.
type RawPrivateKey[Public RawPublicKey[Scheme], Scheme internal.Scheme] interface {
	Pack() []byte
	Scheme() Scheme
	Public() Public
}

func NewPrivate[
	RawPrivate RawPrivateKey[RawPublic, Scheme],
	RawPublic RawPublicKey[Scheme],
	Scheme internal.Scheme,
](sk RawPrivate, pk *PublicKey[RawPublic, Scheme]) PrivateKey[RawPrivate, RawPublic, Scheme] {
	if pk == nil {
		key := NewPublic(sk.Public())
		pk = &key
	}
	return PrivateKey[RawPrivate, RawPublic, Scheme]{
		pk: pk,
		sk: sk,
	}
}

type PrivateKey[
	RawPrivate RawPrivateKey[RawPublic, Scheme],
	RawPublic RawPublicKey[Scheme],
	Scheme internal.Scheme] struct {
	sk RawPrivate
	pk *PublicKey[RawPublic, Scheme]
}

func (p PrivateKey[RawPrivate, RawPublic, Scheme]) Scheme() Scheme  { return p.sk.Scheme() }
func (p PrivateKey[RawPrivate, RawPublic, Scheme]) Raw() RawPrivate { return p.sk }
func (p PrivateKey[RawPrivate, RawPublic, Scheme]) ID() keys.ID     { return (*p.pk).ID() }
func (p PrivateKey[RawPrivate, RawPublic, Scheme]) Fingerprint() keys.Fingerprint {
	return (*p.pk).Fingerprint()
}
func (p PrivateKey[RawPrivate, RawPublic, Scheme]) Public() *PublicKey[RawPublic, Scheme] {
	return p.pk
}
