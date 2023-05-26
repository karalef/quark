package kem

import (
	circlkem "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/karalef/quark/kem/cipher"
)

var (
	kyber512aesgcmScheme = circlScheme{
		Algorithm: Kyber512AESGCM,
		Scheme:    kyber512.Scheme(),
		cipher:    cipher.AESGCM256(),
	}
	kyber512XChaCha20Poly1305Scheme = circlScheme{
		Algorithm: Kyber512XChaCha20Poly1305,
		Scheme:    kyber512.Scheme(),
		cipher:    cipher.XChaCha20Poly1305(),
	}
	kyber768AESGCMScheme = circlScheme{
		Algorithm: Kyber768AESGCM,
		Scheme:    kyber768.Scheme(),
		cipher:    cipher.AESGCM256(),
	}
	kyber768XChaCha20Poly1305Scheme = circlScheme{
		Algorithm: Kyber768XChaCha20Poly1305,
		Scheme:    kyber768.Scheme(),
		cipher:    cipher.XChaCha20Poly1305(),
	}
	kyber1024AESGCMScheme = circlScheme{
		Algorithm: Kyber1024AESGCM,
		Scheme:    kyber1024.Scheme(),
		cipher:    cipher.AESGCM256(),
	}
	kyber1024XChaCha20Poly1305Scheme = circlScheme{
		Algorithm: Kyber1024XChaCha20Poly1305,
		Scheme:    kyber1024.Scheme(),
		cipher:    cipher.XChaCha20Poly1305(),
	}
	frodo640ShakeAESGCMScheme = circlScheme{
		Algorithm: Frodo640ShakeAESGCM,
		Scheme:    frodo640shake.Scheme(),
		cipher:    cipher.AESGCM128(),
	}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	Algorithm
	circlkem.Scheme
	cipher cipher.Scheme
}

func (s circlScheme) Cipher() cipher.Scheme { return s.cipher }

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

func (pub *circlPubKey) Encapsulate(seed []byte) (ciphertext, secret []byte) {
	ct, ss, err := pub.sch.Scheme.EncapsulateDeterministically(pub.pk, seed)
	if err != nil {
		panic(err)
	}
	return ct, ss
}
