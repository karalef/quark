package sign

import (
	"crypto"

	"github.com/cloudflare/circl/sign/dilithium"
)

var (
	dilithium2 = dilithiumScheme{
		Algorithm: Dilithium2,
		Mode:      dilithium.Mode2,
	}
	dilithium2aes = dilithiumScheme{
		Algorithm: Dilithium2AES,
		Mode:      dilithium.Mode2AES,
	}
	dilithium3 = dilithiumScheme{
		Algorithm: Dilithium3,
		Mode:      dilithium.Mode3,
	}
	dilithium3aes = dilithiumScheme{
		Algorithm: Dilithium3AES,
		Mode:      dilithium.Mode3AES,
	}
	dilithium5 = dilithiumScheme{
		Algorithm: Dilithium5,
		Mode:      dilithium.Mode5,
	}
	dilithium5aes = dilithiumScheme{
		Algorithm: Dilithium5AES,
		Mode:      dilithium.Mode5AES,
	}
)

var _ Scheme = dilithiumScheme{}

type dilithiumScheme struct {
	Algorithm
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
	s dilithiumScheme
	dilithium.PrivateKey
}

func (priv *dilithiumPriv) Scheme() Scheme { return priv.s }

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
	return priv.s.Mode.Sign(priv.PrivateKey, msg), nil
}

var _ PublicKey = (*dilithiumPub)(nil)

type dilithiumPub struct {
	s dilithiumScheme
	dilithium.PublicKey
}

func (pub *dilithiumPub) Scheme() Scheme { return pub.s }

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
	return pub.s.Mode.Verify(pub.PublicKey, msg, signature), nil
}
