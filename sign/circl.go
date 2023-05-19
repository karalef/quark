package sign

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

var (
	dilithium2ed25519Scheme = circlScheme{
		Algorithm: Dilithium2ED25519,
		Scheme:    eddilithium2.Scheme(),
	}
	dilithium3ed448Scheme = circlScheme{
		Algorithm: Dilithium3ED448,
		Scheme:    eddilithium3.Scheme(),
	}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	Algorithm
	circlsign.Scheme
}

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey) {
	pub, priv := s.Scheme.DeriveKey(seed)
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

var _ PrivateKey = &circlPrivKey{}

type circlPrivKey struct {
	scheme circlScheme
	circlsign.PrivateKey
}

func (priv *circlPrivKey) Scheme() Scheme { return priv.scheme }

func (priv *circlPrivKey) Equal(p PrivateKey) bool {
	if p, ok := p.(*circlPrivKey); ok {
		return priv.PrivateKey.Equal(p.PrivateKey)
	}
	return false
}

func (priv *circlPrivKey) Bytes() []byte {
	b, _ := priv.PrivateKey.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Sign(msg []byte) ([]byte, error) {
	return priv.scheme.Sign(priv.PrivateKey, msg, nil), nil
}

var _ PublicKey = &circlPubKey{}

type circlPubKey struct {
	scheme circlScheme
	circlsign.PublicKey
}

func (pub *circlPubKey) Scheme() Scheme { return pub.scheme }

func (pub *circlPubKey) Equal(p PublicKey) bool {
	if p, ok := p.(*circlPubKey); ok {
		return pub.PublicKey.Equal(p.PublicKey)
	}
	return false
}

func (pub *circlPubKey) Bytes() []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func (pub *circlPubKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != pub.scheme.SignatureSize() {
		return false, ErrInvalidSignature
	}
	return pub.scheme.Verify(pub.PublicKey, msg, signature, nil), nil
}
