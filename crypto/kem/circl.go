package kem

import (
	circlkem "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(Kyber512)
	Register(Kyber768)
	Register(Kyber1024)
	Register(Frodo640Shake)
}

// kem schemes.
var (
	Kyber512      = circlScheme{"Kyber512", kyber512.Scheme()}
	Kyber768      = circlScheme{"Kyber768", kyber768.Scheme()}
	Kyber1024     = circlScheme{"Kyber1024", kyber1024.Scheme()}
	Frodo640Shake = circlScheme{"Frodo640SHAKE", frodo640shake.Scheme()}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	scheme.StringName
	scheme circlkem.Scheme
}

func (s circlScheme) CiphertextSize() int        { return s.scheme.CiphertextSize() }
func (s circlScheme) SharedSecretSize() int      { return s.scheme.SharedKeySize() }
func (s circlScheme) EncapsulationSeedSize() int { return s.scheme.EncapsulationSeedSize() }
func (s circlScheme) PrivateKeySize() int        { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int         { return s.scheme.PublicKeySize() }
func (s circlScheme) SeedSize() int              { return s.scheme.SeedSize() }

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.scheme.DeriveKeyPair(seed)
	pk, sk := newKeys(&circlPubKey{pub, s}, &circlPrivKey{priv, s})
	return sk, pk, nil
}

func (s circlScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	pub, err := s.scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return newPub(&circlPubKey{sch: s, pk: pub}), nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	_, sk := newKeys(nil, &circlPrivKey{priv, s})
	return sk, nil
}

var _ rawPrivateKey = &circlPrivKey{}

type circlPrivKey struct {
	sk  circlkem.PrivateKey
	sch circlScheme
}

func (priv *circlPrivKey) Scheme() crypto.Scheme { return priv.sch }

func (priv *circlPrivKey) Public() rawPublicKey {
	return &circlPubKey{priv.sk.Public(), priv.sch}
}

func (priv *circlPrivKey) Pack() []byte {
	b, _ := priv.sk.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Equal(p rawPrivateKey) bool {
	pk, ok := p.(*circlPrivKey)
	return ok && priv.sk.Equal(pk.sk)
}

func (priv *circlPrivKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != priv.sch.CiphertextSize() {
		return nil, ErrCiphertext
	}
	return priv.sch.scheme.Decapsulate(priv.sk, ciphertext)
}

var _ rawPublicKey = &circlPubKey{}

type circlPubKey struct {
	pk  circlkem.PublicKey
	sch circlScheme
}

func (pub *circlPubKey) Scheme() crypto.Scheme { return pub.sch }

func (pub *circlPubKey) Pack() []byte {
	b, _ := pub.pk.MarshalBinary()
	return b
}

func (pub *circlPubKey) Equal(p rawPublicKey) bool {
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
	ct, ss, err := pub.sch.scheme.EncapsulateDeterministically(pub.pk, seed)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}
