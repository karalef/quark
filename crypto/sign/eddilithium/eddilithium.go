package eddilithium

import (
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/sign/stream"
	"github.com/karalef/quark/scheme"
)

var (
	// ED25519Mode2 is the hybrid signature scheme of ED25519 and Dilithium in mode 2.
	ED25519Mode2 = circlScheme{"ED25519_Dilithium2", eddilithium2.Scheme()}
	// ED448Mode3 is the hybrid signature scheme of ED448 and Dilithium in mode 3.
	ED448Mode3 = circlScheme{"ED448_Dilithium3", eddilithium3.Scheme()}
)

var _ sign.Scheme = circlScheme{}

type circlScheme struct {
	scheme.String
	scheme circlsign.Scheme
}

func (s circlScheme) PrivateKeySize() int { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int  { return s.scheme.PublicKeySize() }
func (s circlScheme) SeedSize() int       { return s.scheme.SeedSize() }
func (s circlScheme) Size() int           { return s.scheme.SignatureSize() }

func (s circlScheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic(sign.ErrSeedSize)
	}
	pub, priv := s.scheme.DeriveKey(seed)
	pk := circlPubKey{pk: circlPublicKey{pub}, scheme: s}
	return pk, circlPrivKey{circlPrivateKey{priv}, pk}
}

func (s circlScheme) UnpackPublic(key []byte) (sign.PublicKey, error) {
	pub, err := s.scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, sign.ErrKeySize
	}
	return circlPubKey{pk: circlPublicKey{pub}, scheme: s}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (sign.PrivateKey, error) {
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, sign.ErrKeySize
	}
	pk := circlPubKey{pk: circlPublicKey{priv.Public().(circlsign.PublicKey)}, scheme: s}
	return circlPrivKey{circlPrivateKey{priv}, pk}, nil
}

type circlPrivateKey struct{ circlsign.PrivateKey }

func (k circlPrivateKey) Sign(msg []byte) []byte {
	return k.PrivateKey.Scheme().Sign(k.PrivateKey, msg, nil)
}

var _ sign.PrivateKey = (*circlPrivKey)(nil)

type circlPrivKey struct {
	sk  circlPrivateKey
	pub circlPubKey
}

func (k circlPrivKey) Scheme() sign.Scheme    { return k.pub.Scheme() }
func (k circlPrivKey) Public() sign.PublicKey { return k.pub }

func (k circlPrivKey) Pack() []byte {
	b, _ := k.sk.MarshalBinary()
	return b
}

func (k circlPrivKey) Sign() sign.Signer {
	return stream.StreamSigner(k.sk, hash.SHA3_512)
}

func (k circlPrivKey) Equal(other sign.PrivateKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPrivKey)
	return ok && k.sk.Equal(o.sk.PrivateKey)
}

type circlPublicKey struct{ circlsign.PublicKey }

func (pub circlPublicKey) Verify(msg, sig []byte) (bool, error) {
	if len(sig) != pub.Scheme().SignatureSize() {
		return false, sign.ErrSignature
	}
	return pub.Scheme().Verify(pub.PublicKey, msg, sig, nil), nil
}

var _ sign.PublicKey = circlPubKey{}

type circlPubKey struct {
	pk     circlPublicKey
	scheme circlScheme
}

func (pub circlPubKey) Scheme() sign.Scheme { return pub.scheme }

func (pub circlPubKey) Pack() []byte {
	b, _ := pub.pk.MarshalBinary()
	return b
}

func (pub circlPubKey) Verify() sign.Verifier {
	return stream.StreamVerifier(pub.pk, hash.SHA3_512)
}

func (pub circlPubKey) Equal(other sign.PublicKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPubKey)
	return ok && pub.pk.Equal(o.pk.PublicKey)
}
