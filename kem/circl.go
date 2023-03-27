package kem

import (
	"io"

	circlkem "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

var (
	kyber512Scheme = circlScheme{
		Algorithm: Kyber512,
		Scheme:    kyber512.Scheme(),
	}
	kyber768Scheme = circlScheme{
		Algorithm: Kyber768,
		Scheme:    kyber768.Scheme(),
	}
	kyber1024Scheme = circlScheme{
		Algorithm: Kyber1024,
		Scheme:    kyber1024.Scheme(),
	}
	frodoScheme = circlScheme{
		Algorithm: Frodo,
		Scheme:    frodo640shake.Scheme(),
	}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	Algorithm
	circlkem.Scheme
}

func (s circlScheme) GenerateKey(rand io.Reader) (PrivateKey, PublicKey, error) {
	seed := make([]byte, s.SeedSize())
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv, pub := s.DeriveKey(seed)
	return priv, pub, nil
}

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey) {
	pub, priv := s.Scheme.DeriveKeyPair(seed)
	return &circlPrivKey{s, priv}, &circlPubKey{s, pub}
}

func (s circlScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub, err := s.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPubKey{
		scheme:    s,
		PublicKey: pub,
	}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	priv, err := s.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPrivKey{
		scheme:     s,
		PrivateKey: priv,
	}, nil
}

func (s circlScheme) EncapsKeySize() int { return s.Scheme.CiphertextSize() }

var _ PrivateKey = &circlPrivKey{}

type circlPrivKey struct {
	scheme circlScheme
	circlkem.PrivateKey
}

func (priv *circlPrivKey) Public() PublicKey {
	return &circlPubKey{
		scheme:    priv.scheme,
		PublicKey: priv.PrivateKey.Public().(circlkem.PublicKey),
	}
}

func (priv *circlPrivKey) Scheme() Scheme { return priv.scheme }

func (priv *circlPrivKey) Pack() []byte {
	b, _ := priv.PrivateKey.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Equal(p PrivateKey) bool {
	pk, ok := p.(*circlPrivKey)
	if !ok {
		return false
	}
	return priv.PrivateKey.Equal(pk.PrivateKey)
}

func (priv *circlPrivKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return priv.scheme.Scheme.Decapsulate(priv.PrivateKey, ciphertext)
}

var _ PublicKey = &circlPubKey{}

type circlPubKey struct {
	scheme circlScheme
	circlkem.PublicKey
}

func (pub *circlPubKey) Scheme() Scheme { return pub.scheme }

func (pub *circlPubKey) Pack() []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func (pub *circlPubKey) Equal(p PublicKey) bool {
	pk, ok := p.(*circlPubKey)
	if !ok {
		return false
	}
	return pub.PublicKey.Equal(pk.PublicKey)
}

func (pub *circlPubKey) Encapsulate() (ciphertext, secret []byte, err error) {
	return pub.scheme.Scheme.Encapsulate(pub.PublicKey)
}
