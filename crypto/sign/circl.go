package sign

import (
	circlsign "github.com/karalef/circl/sign"
	"github.com/karalef/circl/sign/dilithium"
)

var (
	// Dilithium2 is the Dilithium signature scheme in mode 2.
	Dilithium2 = circlScheme{"Dilithium2", dilithium.Mode2}
	// Dilithium2AES is the Dilithium signature scheme in mode 2 with AES.
	Dilithium2AES = circlScheme{"Dilithium2_AES", dilithium.Mode2AES}
	// Dilithium3 is the Dilithium signature scheme in mode 3.
	Dilithium3 = circlScheme{"Dilithium3", dilithium.Mode3}
	// Dilithium3AES is the Dilithium signature scheme in mode 3 with AES.
	Dilithium3AES = circlScheme{"Dilithium3_AES", dilithium.Mode2AES}
	// Dilithium5 is the Dilithium signature scheme in mode 5.
	Dilithium5 = circlScheme{"Dilithium5", dilithium.Mode5}
	// Dilithium5AES is the Dilithium signature scheme in mode 5 with AES.
	Dilithium5AES = circlScheme{"Dilithium5_AES", dilithium.Mode5AES}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	name string
	circlsign.Scheme
}

func (s circlScheme) Name() string { return s.name }

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

func (priv *circlPrivKey) Signer() Signer {
	return priv.scheme.Signer(priv.PrivateKey)
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

func (pub *circlPubKey) Verifier() Verifier {
	return circlVerifier{
		scheme:   pub.scheme,
		Verifier: pub.scheme.Verifier(pub.PublicKey),
	}
}

var _ Verifier = circlVerifier{}

type circlVerifier struct {
	scheme Scheme
	circlsign.Verifier
}

func (v circlVerifier) Verify(signature []byte) (bool, error) {
	if len(signature) != v.scheme.SignatureSize() {
		return false, ErrSignature
	}
	return v.Verifier.Verify(signature), nil
}
