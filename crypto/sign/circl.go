package sign

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign/stream"
	"github.com/karalef/quark/scheme"
)

var (
	// EDDilithium2 is the hybrid signature scheme of ED25519 and Dilithium in mode 2.
	EDDilithium2 = circlScheme{"ED25519_Dilithium2", eddilithium2.Scheme()}
	// EDDilithium3 is the hybrid signature scheme of ED448 and Dilithium in mode 3.
	EDDilithium3 = circlScheme{"ED448_Dilithium3", eddilithium3.Scheme()}
)

func init() {
	Register(EDDilithium2)
	Register(EDDilithium3)
}

var _ Scheme = (*circlScheme)(nil)

type circlScheme struct {
	scheme.String
	scheme circlsign.Scheme
}

func (s circlScheme) PrivateKeySize() int { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int  { return s.scheme.PublicKeySize() }
func (s circlScheme) SignatureSize() int  { return s.scheme.SignatureSize() }
func (s circlScheme) SeedSize() int       { return s.scheme.SeedSize() }

func (s circlScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	pub, priv := s.scheme.DeriveKey(seed)
	pk := &circlPubKey{crypto.NewKeyID(&circlPublicKey{pub, s})}
	return &circlPrivKey{circlPrivateKey{priv}, pk}, pk, nil
}

func (s circlScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub, err := s.scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &circlPubKey{crypto.NewKeyID(&circlPublicKey{pub, s})}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pub := &circlPublicKey{priv.Public().(circlsign.PublicKey), s}
	return &circlPrivKey{circlPrivateKey{priv}, &circlPubKey{crypto.NewKeyID(pub)}}, nil
}

var _ PrivateKey = (*circlPrivKey)(nil)

type circlPrivateKey struct {
	circlsign.PrivateKey
}

func (k circlPrivateKey) Pack() []byte {
	b, _ := k.PrivateKey.MarshalBinary()
	return b
}

func (k circlPrivateKey) Sign(msg []byte) []byte {
	return k.PrivateKey.Scheme().Sign(k.PrivateKey, msg, nil)
}

type circlPrivKey struct {
	circlPrivateKey
	pub *circlPubKey
}

func (priv *circlPrivKey) ID() crypto.ID                   { return priv.pub.ID() }
func (priv *circlPrivKey) Fingerprint() crypto.Fingerprint { return priv.pub.Fingerprint() }
func (priv *circlPrivKey) Scheme() crypto.Scheme           { return priv.pub.Scheme() }
func (priv *circlPrivKey) Public() PublicKey               { return priv.pub }

func (priv *circlPrivKey) Equal(p PrivateKey) bool {
	if p == nil {
		return false
	}
	pk, ok := p.(*circlPrivKey)
	if !ok {
		return false
	}
	if priv == pk {
		return true
	}
	if priv == nil || pk == nil {
		return false
	}
	return priv.PrivateKey.Equal(pk.PrivateKey)
}

func (priv *circlPrivKey) Sign() Signer {
	return stream.StreamSigner(priv.circlPrivateKey, hash.SHA3_512)
}

type circlPublicKey struct {
	circlsign.PublicKey
	scheme circlScheme
}

func (pub *circlPublicKey) Scheme() crypto.Scheme { return pub.scheme }

func (pub circlPublicKey) Pack() []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func (pub circlPublicKey) Verify(msg, signature []byte) (bool, error) {
	return pub.scheme.scheme.Verify(pub.PublicKey, msg, signature, nil), nil
}

var _ PublicKey = (*circlPubKey)(nil)

type circlPubKey struct {
	crypto.KeyID[*circlPublicKey]
}

func (pub *circlPubKey) Equal(pk PublicKey) bool {
	if pk == nil {
		return false
	}
	p, ok := pk.(*circlPubKey)
	if !ok {
		return false
	}
	if pub == p {
		return true
	}
	if pub == nil || p == nil {
		return false
	}
	return pub.PublicKey.Equal(p.PublicKey.PublicKey)
}

func (pub *circlPubKey) Verify() Verifier {
	return stream.StreamVerifier(pub.PublicKey, hash.SHA3_512)
}
