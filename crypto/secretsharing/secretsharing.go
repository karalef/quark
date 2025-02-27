// Package secretsharing provides methods to split secrets into shares.
// In this implementation, secret sharing is defined over the scalar field of
// a prime order group.
package secretsharing

import (
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

type Scheme interface {
	scheme.Scheme

	// Size returns the size of the secret.
	Size() uint

	// New creates a secret sharing. It allows splitting a secret into shares,
	// such that the secret can be only recovered from any subset of k shares.
	// The secret lengths must be of Scheme.Size() bytes.
	New(k uint, secret []byte) Sharing

	// Verify returns true if the share s was produced by sharing a secret with
	// this scheme, specified k and commitment of the secret c.
	Verify(k uint, s Share, c Commit) bool

	// Recover returns a secret provided equal or more than k different shares
	// are given. Panics if the number of shares is less than k or if some
	// shares are duplicated, i.e., shares must have different IDs.
	Recover(k uint, shares []Share) []byte
}

// Sharing provides a (k,n) Shamir's secret sharing. It allows splitting a
// secret into n shares, such that the secret can be only recovered from any
// subset of k shares.
type Sharing interface {
	// Share creates n shares with an ID monotonically increasing from 1 to n.
	Share(n uint) []Share

	// ShareWithID creates one share of the secret using the ID as identifier.
	// Notice that shares with the same ID are considered equal.
	// Panics, if the ID is zero.
	ShareWithID(id uint64) Share

	// Commit creates a commitment of the secret for further verifying shares.
	Commit() Commit
}

type sharing struct {
	g group.Group
	p polynomial.Polynomial
}

func (s sharing) Share(n uint) []Share {
	shares := make([]Share, n)
	id := s.g.NewScalar()
	for i := range shares {
		uid := uint64(i + 1)
		shares[i] = s.shareWithID(uid, id.SetUint64(uid))
	}
	return shares
}

func (s sharing) ShareWithID(id uint64) Share {
	return s.shareWithID(id, s.g.NewScalar().SetUint64(id))
}

func (s sharing) shareWithID(uid uint64, id group.Scalar) Share {
	if id.IsZero() {
		panic("secretsharing: id cannot be zero")
	}
	return Share{
		ID:    uid,
		Value: crypto.OrPanic(s.p.Evaluate(id).MarshalBinary()),
	}
}

func (s sharing) Commit() Commit {
	c := make(Commit, s.p.Degree()+1)
	for i := range c {
		el := s.g.NewElement().MulGen(s.p.Coefficient(uint(i)))
		c[i] = crypto.OrPanic(el.MarshalBinary())
	}
	return c
}

// Share is a share of a secret.
type Share struct {
	// ID is the unique identifier of the share. It cannot be zero.
	ID uint64

	// Value is the value of the share.
	Value []byte
}

// Commit is a secret commitment.
type Commit [][]byte

var _ Scheme = sharingScheme{}

type sharingScheme struct {
	scheme.String
	g group.Group
}

func (s sharingScheme) Size() uint { return s.g.Params().ScalarLength }

func (s sharingScheme) New(k uint, secret []byte) Sharing {
	if len(secret) != int(s.Size()) {
		panic("secretsharing: wrong secret size")
	}

	c := make([]group.Scalar, k)
	c[0] = s.g.NewScalar()
	if err := c[0].UnmarshalBinary(secret); err != nil {
		panic(err)
	}
	rnd := crypto.Reader(nil)
	for i := 1; i < len(c); i++ {
		c[i] = s.g.RandomScalar(rnd)
	}

	return sharing{g: s.g, p: polynomial.New(c)}
}

func (s sharingScheme) Verify(k uint, sh Share, com Commit) bool {
	if sh.ID == 0 || len(com) != int(k) {
		return false
	}
	if len(sh.Value) != int(s.Size()) ||
		len(com[0]) != int(s.g.Params().ElementLength) {
		return false
	}

	lc := len(com) - 1
	sum := s.g.NewElement()
	if err := sum.UnmarshalBinary(com[lc]); err != nil {
		return false
	}
	id := s.g.NewScalar()
	comEl := s.g.NewElement()
	for i := lc - 1; i >= 0; i-- {
		sum.Mul(sum, id.SetUint64(sh.ID))
		if err := comEl.UnmarshalBinary(com[i]); err != nil {
			return false
		}
		sum.Add(sum, comEl)
	}
	val := id
	if err := val.UnmarshalBinary(sh.Value); err != nil {
		return false
	}
	polI := s.g.NewElement().MulGen(val)
	return polI.IsEqual(sum)
}

func (s sharingScheme) Recover(k uint, shares []Share) []byte {
	if l := len(shares); l < int(k) {
		panic("secretsharing: number of shares must be equal or above the k")
	}

	x := make([]group.Scalar, k)
	px := make([]group.Scalar, k)
	for i := range shares[:k] {
		x[i] = s.g.NewScalar().SetUint64(shares[i].ID)
		px[i] = s.g.NewScalar()
		if err := px[i].UnmarshalBinary(shares[i].Value); err != nil {
			panic(err)
		}
	}

	l := polynomial.NewLagrangePolynomial(x, px)
	return crypto.OrPanic(l.Evaluate(s.g.NewScalar()).MarshalBinary())
}
