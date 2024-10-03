package sign

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(EDDilithium2)
	Register(EDDilithium3)
}

var (
	// EDDilithium2 is the hybrid signature scheme of ED25519 and Dilithium in mode 2.
	EDDilithium2 = circlScheme{"ED25519_Dilithium2", eddilithium2.Scheme()}
	// EDDilithium3 is the hybrid signature scheme of ED448 and Dilithium in mode 3.
	EDDilithium3 = circlScheme{"ED448_Dilithium3", eddilithium3.Scheme()}
)

var _ Scheme = circlScheme{}

type circlScheme struct {
	scheme.StringName
	scheme circlsign.Scheme
}

func (s circlScheme) PrivateKeySize() int { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int  { return s.scheme.PublicKeySize() }
func (s circlScheme) SignatureSize() int  { return s.scheme.SignatureSize() }
func (s circlScheme) SeedSize() int       { return s.scheme.SeedSize() }

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.scheme.DeriveKey(seed)
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
	return newPub(&circlPubKey{pub, s}), nil
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
	circlsign.PrivateKey
	scheme circlScheme
}

func (priv *circlPrivKey) Scheme() crypto.Scheme { return priv.scheme }

func (priv *circlPrivKey) Public() rawPublicKey {
	return &circlPubKey{priv.PrivateKey.Public().(circlsign.PublicKey), priv.scheme}
}

func (priv *circlPrivKey) Equal(p rawPrivateKey) bool {
	if p, ok := p.(*circlPrivKey); ok {
		return priv.PrivateKey.Equal(p.PrivateKey)
	}
	return false
}

func (priv *circlPrivKey) Pack() []byte {
	b, _ := priv.PrivateKey.MarshalBinary()
	return b
}

func (priv *circlPrivKey) Sign(data []byte) []byte {
	return priv.scheme.scheme.Sign(priv.PrivateKey, data, nil)
}

var _ rawPublicKey = &circlPubKey{}

type circlPubKey struct {
	circlsign.PublicKey
	scheme circlScheme
}

func (pub *circlPubKey) Scheme() crypto.Scheme { return pub.scheme }

func (pub *circlPubKey) Equal(p rawPublicKey) bool {
	if p, ok := p.(*circlPubKey); ok {
		return pub.PublicKey.Equal(p.PublicKey)
	}
	return false
}

func (pub *circlPubKey) Pack() []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func (pub *circlPubKey) Verify(message, signature []byte) (bool, error) {
	if len(signature) != pub.scheme.SignatureSize() {
		return false, ErrSignature
	}
	return pub.scheme.scheme.Verify(pub.PublicKey, message, signature, nil), nil
}
