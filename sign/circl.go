package sign

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

var (
	dilithium2ed25519Scheme = circlScheme{eddilithium2.Scheme()}
	dilithium3ed448Scheme   = circlScheme{eddilithium3.Scheme()}
)

// EDDilithium2 returns the hybrid signature scheme ed25519 with Dilithium2.
func EDDilithium2() Scheme { return dilithium2ed25519Scheme }

// EDDilithium3 returns the hybrid signature scheme ed448 with Dilithium3.
func EDDilithium3() Scheme { return dilithium3ed448Scheme }

var _ Scheme = circlScheme{}

type circlScheme struct {
	circlsign.Scheme
}

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.Scheme.DeriveKey(seed)
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
	return &circlPubKey{s, pub}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv, err := s.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPrivKey{s, priv}, nil
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
		return false, ErrSignature
	}
	return pub.scheme.Verify(pub.PublicKey, msg, signature, nil), nil
}
