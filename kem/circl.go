package kem

import (
	circlkem "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Kyber512 returns the Kyber512 scheme.
func Kyber512() Scheme { return circlScheme{kyber512.Scheme()} }

// Kyber768 returns the Kyber768 scheme.
func Kyber768() Scheme { return circlScheme{kyber768.Scheme()} }

// Kyber1024 returns the Kyber1024 scheme.
func Kyber1024() Scheme { return circlScheme{kyber1024.Scheme()} }

// Frodo640Shake returns the variant FrodoKEM-640 with SHAKE.
func Frodo640Shake() Scheme { return circlScheme{frodo640shake.Scheme()} }

var _ Scheme = circlScheme{}

type circlScheme struct {
	circlkem.Scheme
}

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.Scheme.DeriveKeyPair(seed)
	return &circlPrivKey{s, priv}, &circlPubKey{s, pub}, nil
}

func (s circlScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	pub, err := s.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPubKey{
		sch: s,
		pk:  pub,
	}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv, err := s.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPrivKey{
		sch: s,
		sk:  priv,
	}, nil
}

func (s circlScheme) SharedSecretSize() int { return s.Scheme.SharedKeySize() }

var _ PrivateKey = &circlPrivKey{}

type circlPrivKey struct {
	sch circlScheme
	sk  circlkem.PrivateKey
}

func (priv *circlPrivKey) Scheme() Scheme { return priv.sch }

func (priv *circlPrivKey) Bytes() []byte {
	b, _ := priv.sk.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Equal(p PrivateKey) bool {
	pk, ok := p.(*circlPrivKey)
	return ok && priv.sk.Equal(pk.sk)
}

func (priv *circlPrivKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return priv.sch.Decapsulate(priv.sk, ciphertext)
}

var _ PublicKey = &circlPubKey{}

type circlPubKey struct {
	sch circlScheme
	pk  circlkem.PublicKey
}

func (pub *circlPubKey) Scheme() Scheme { return pub.sch }

func (pub *circlPubKey) Bytes() []byte {
	b, _ := pub.pk.MarshalBinary()
	return b
}

func (pub *circlPubKey) Equal(p PublicKey) bool {
	pk, ok := p.(*circlPubKey)
	if !ok {
		return false
	}
	return pub.pk.Equal(pk.pk)
}

func (pub *circlPubKey) Encapsulate(seed []byte) (ciphertext, secret []byte, err error) {
	if len(seed) != pub.sch.EncapsulationSeedSize() {
		return nil, nil, ErrEncapsulationSeed
	}
	ct, ss, err := pub.sch.Scheme.EncapsulateDeterministically(pub.pk, seed)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}
