package sign

import (
	"crypto"

	"github.com/cloudflare/circl/sign/dilithium"
)

// Dilithium2 returns the Dilithium2 signature scheme.
func Dilithium2() Scheme { return dilithiumScheme{dilithium.Mode2} }

// Dilithium2AES returns the Dilithium2-AES signature scheme.
func Dilithium2AES() Scheme { return dilithiumScheme{dilithium.Mode2AES} }

// Dilithium3 returns the Dilithium3 signature scheme.
func Dilithium3() Scheme { return dilithiumScheme{dilithium.Mode3} }

// Dilithium3AES returns the Dilithium3-AES signature scheme.
func Dilithium3AES() Scheme { return dilithiumScheme{dilithium.Mode3AES} }

// Dilithium5 returns the Dilithium5 signature scheme.
func Dilithium5() Scheme { return dilithiumScheme{dilithium.Mode5} }

// Dilithium5AES returns the Dilithium5-AES signature scheme.
func Dilithium5AES() Scheme { return dilithiumScheme{dilithium.Mode5AES} }

var _ Scheme = dilithiumScheme{}

type dilithiumScheme struct {
	dilithium.Mode
}

func (s dilithiumScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.Mode.NewKeyFromSeed(seed)
	return &dilithiumPriv{s, priv}, &dilithiumPub{s, pub}, nil
}

func (s dilithiumScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	return &dilithiumPub{s, s.Mode.PublicKeyFromBytes(key)}, nil
}

func (s dilithiumScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	return &dilithiumPriv{s, s.Mode.PrivateKeyFromBytes(key)}, nil
}

type cryptoEqualer interface {
	Equal(crypto.PublicKey) bool
}

var _ PrivateKey = (*dilithiumPriv)(nil)

type dilithiumPriv struct {
	scheme dilithiumScheme
	dilithium.PrivateKey
}

func (priv *dilithiumPriv) Scheme() Scheme { return priv.scheme }

func (priv *dilithiumPriv) Equal(p PrivateKey) bool {
	other, ok := p.(*dilithiumPriv)
	if !ok {
		return false
	}
	if e, ok := priv.PrivateKey.(cryptoEqualer); ok {
		return e.Equal(other.PrivateKey)
	}
	return string(priv.Bytes()) == string(p.Bytes())
}

func (priv *dilithiumPriv) Sign(msg []byte) ([]byte, error) {
	return priv.scheme.Mode.Sign(priv.PrivateKey, msg), nil
}

var _ PublicKey = (*dilithiumPub)(nil)

type dilithiumPub struct {
	scheme dilithiumScheme
	dilithium.PublicKey
}

func (pub *dilithiumPub) Scheme() Scheme { return pub.scheme }

func (pub *dilithiumPub) Equal(p PublicKey) bool {
	other, ok := p.(*dilithiumPub)
	if !ok {
		return false
	}
	if e, ok := pub.PublicKey.(cryptoEqualer); ok {
		return e.Equal(other.PublicKey)
	}
	return string(pub.Bytes()) == string(p.Bytes())
}

func (pub *dilithiumPub) Verify(msg []byte, signature []byte) (bool, error) {
	if len(signature) != pub.scheme.SignatureSize() {
		return false, ErrSignature
	}
	return pub.scheme.Mode.Verify(pub.PublicKey, msg, signature), nil
}
