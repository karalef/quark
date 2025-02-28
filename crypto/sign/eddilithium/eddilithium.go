package eddilithium

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign/internal"
	"github.com/karalef/quark/crypto/sign/stream"
	"github.com/karalef/quark/scheme"
)

var (
	// ED25519Mode2 is the hybrid signature scheme of ED25519 and Dilithium in mode 2.
	ED25519Mode2 = circlScheme{"ED25519_Dilithium2", eddilithium2.Scheme()}
	// ED448Mode3 is the hybrid signature scheme of ED448 and Dilithium in mode 3.
	ED448Mode3 = circlScheme{"ED448_Dilithium3", eddilithium3.Scheme()}
)

var _ internal.Scheme = circlScheme{}

type circlScheme struct {
	scheme.String
	scheme circlsign.Scheme
}

func (s circlScheme) PrivateKeySize() int { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int  { return s.scheme.PublicKeySize() }
func (s circlScheme) SeedSize() int       { return s.scheme.SeedSize() }
func (s circlScheme) Size() int           { return s.scheme.SignatureSize() }

func (s circlScheme) DeriveKey(seed []byte) (internal.PublicKey, internal.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic(internal.ErrSeedSize)
	}
	pub, priv := s.scheme.DeriveKey(seed)
	pk := circlPubKey{pk: circlPublicKey{pub}, scheme: s}
	return pk, circlPrivKey{circlPrivateKey{priv}, pk}
}

func (s circlScheme) UnpackPublic(key []byte) (internal.PublicKey, error) {
	pub, err := s.scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, internal.ErrKeySize
	}
	return circlPubKey{pk: circlPublicKey{pub}, scheme: s}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (internal.PrivateKey, error) {
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, internal.ErrKeySize
	}
	pk := circlPubKey{pk: circlPublicKey{priv.Public().(circlsign.PublicKey)}, scheme: s}
	return circlPrivKey{circlPrivateKey{priv}, pk}, nil
}

type circlPrivateKey struct{ circlsign.PrivateKey }

func (k circlPrivateKey) Sign(msg []byte) []byte {
	return k.PrivateKey.Scheme().Sign(k.PrivateKey, msg, nil)
}

var _ internal.PrivateKey = (*circlPrivKey)(nil)

type circlPrivKey struct {
	sk  circlPrivateKey
	pub circlPubKey
}

func (k circlPrivKey) Scheme() internal.Scheme    { return k.pub.Scheme() }
func (k circlPrivKey) Public() internal.PublicKey { return k.pub }

func (k circlPrivKey) Pack() []byte {
	b, _ := k.sk.MarshalBinary()
	return b
}

func (k circlPrivKey) Sign() internal.Signer {
	return stream.StreamSigner(k.sk, hash.SHA3_512)
}

func (k circlPrivKey) Equal(other internal.PrivateKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPrivKey)
	return ok && k.sk.Equal(o.sk.PrivateKey)
}

type circlPublicKey struct{ circlsign.PublicKey }

func (pub circlPublicKey) Verify(msg, sig []byte) (bool, error) {
	if len(sig) != pub.Scheme().SignatureSize() {
		return false, internal.ErrSignature
	}
	return pub.Scheme().Verify(pub.PublicKey, msg, sig, nil), nil
}

var _ internal.PublicKey = circlPubKey{}

type circlPubKey struct {
	pk     circlPublicKey
	scheme circlScheme
}

func (pub circlPubKey) Scheme() internal.Scheme { return pub.scheme }

func (pub circlPubKey) Pack() []byte {
	b, _ := pub.pk.MarshalBinary()
	return b
}

func (pub circlPubKey) Verify() internal.Verifier {
	return stream.StreamVerifier(pub.pk, hash.SHA3_512)
}

func (pub circlPubKey) Equal(other internal.PublicKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPubKey)
	return ok && pub.pk.Equal(o.pk.PublicKey)
}
