package kem

import (
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
		Algorithm: Frodo640,
		Scheme:    frodo640shake.Scheme(),
	}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	Algorithm
	circlkem.Scheme
}

func (s circlScheme) GenerateKey() (PrivateKey, PublicKey, error) {
	pub, priv, err := s.Scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pk := &circlPubKey{
		scheme: s,
		pk:     pub,
	}
	return &circlPrivKey{pk: pk, sk: priv}, pk, nil
}

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey) {
	pub, priv := s.Scheme.DeriveKeyPair(seed)
	pk := &circlPubKey{
		scheme: s,
		pk:     pub,
	}
	return &circlPrivKey{pk: pk, sk: priv}, pk
}

func (s circlScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub, err := s.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPubKey{
		scheme: s,
		pk:     pub,
	}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	priv, err := s.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPrivKey{
		pk: &circlPubKey{
			scheme: s,
			pk:     priv.Public(),
		},
		sk: priv,
	}, nil
}

func (s circlScheme) SharedSecretSize() int { return s.Scheme.SharedKeySize() }

var _ PrivateKey = &circlPrivKey{}

type circlPrivKey struct {
	pk *circlPubKey
	sk circlkem.PrivateKey
}

func (priv *circlPrivKey) Public() PublicKey { return priv.pk }
func (priv *circlPrivKey) Scheme() Scheme    { return priv.pk.scheme }

func (priv *circlPrivKey) Bytes() []byte {
	b, _ := priv.sk.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Equal(p PrivateKey) bool {
	pk, ok := p.(*circlPrivKey)
	return ok && priv.sk.Equal(pk.sk)
}

func (priv *circlPrivKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return priv.pk.scheme.Decapsulate(priv.sk, ciphertext)
}

var _ PublicKey = &circlPubKey{}

type circlPubKey struct {
	scheme circlScheme
	pk     circlkem.PublicKey
}

func (pub *circlPubKey) Scheme() Scheme { return pub.scheme }

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

func (pub *circlPubKey) Encapsulate() (ciphertext, secret []byte, err error) {
	return pub.scheme.Scheme.Encapsulate(pub.pk)
}
