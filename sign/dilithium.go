package sign

import (
	"io"

	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

var (
	dilithium2ed25519Scheme = dilithiumScheme{
		Algorithm: Dilithium2,
		Scheme:    eddilithium2.Scheme(),
	}
	dilithium3ed448Scheme = dilithiumScheme{
		Algorithm: Dilithium3,
		Scheme:    eddilithium3.Scheme(),
	}
)

var _ Scheme = dilithiumScheme{}

type dilithiumScheme struct {
	Algorithm
	circlsign.Scheme
}

func (s dilithiumScheme) GenerateKey(rand io.Reader) (PrivateKey, PublicKey, error) {
	seed := make([]byte, s.SeedSize())
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv, pub := s.DeriveKey(seed)
	return priv, pub, nil
}

func (s dilithiumScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey) {
	pub, priv := s.Scheme.DeriveKey(seed)
	return &dilithiumPrivKey{s, priv}, &dilithiumPubKey{s, pub}
}

func (s dilithiumScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub, err := s.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &dilithiumPubKey{
		scheme:    s,
		PublicKey: pub,
	}, nil
}

func (s dilithiumScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	priv, err := s.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &dilithiumPrivKey{
		scheme:     s,
		PrivateKey: priv,
	}, nil
}

var _ PrivateKey = &dilithiumPrivKey{}

type dilithiumPrivKey struct {
	scheme dilithiumScheme
	circlsign.PrivateKey
}

func (priv *dilithiumPrivKey) Public() PublicKey {
	return &dilithiumPubKey{
		scheme:    priv.scheme,
		PublicKey: priv.PrivateKey.Public().(circlsign.PublicKey),
	}
}

func (priv *dilithiumPrivKey) Scheme() Scheme          { return priv.scheme }
func (priv *dilithiumPrivKey) Equal(p PrivateKey) bool { return priv.PrivateKey.Equal(p) }
func (priv *dilithiumPrivKey) Pack() []byte {
	b, _ := priv.PrivateKey.MarshalBinary()
	return b
}

func (priv *dilithiumPrivKey) Sign(msg []byte) ([]byte, error) {
	return priv.scheme.Scheme.Sign(priv.PrivateKey, msg, nil), nil
}

var _ PublicKey = &dilithiumPubKey{}

type dilithiumPubKey struct {
	scheme dilithiumScheme
	circlsign.PublicKey
}

func (pub *dilithiumPubKey) Scheme() Scheme         { return pub.scheme }
func (pub *dilithiumPubKey) Equal(p PublicKey) bool { return pub.PublicKey.Equal(p) }
func (pub *dilithiumPubKey) Pack() []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func (pub *dilithiumPubKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != pub.scheme.SignatureSize() {
		return false, ErrInvalidSignature
	}
	return pub.scheme.Verify(pub.PublicKey, msg, signature, nil), nil
}
