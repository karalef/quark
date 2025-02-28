package circl

import (
	circlkem "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/karalef/quark/crypto/kem/internal"
	"github.com/karalef/quark/scheme"
)

// kem schemes.
var (
	Kyber512      = circlScheme{"Kyber512", kyber512.Scheme()}
	Kyber768      = circlScheme{"Kyber768", kyber768.Scheme()}
	Kyber1024     = circlScheme{"Kyber1024", kyber1024.Scheme()}
	Frodo640Shake = circlScheme{"Frodo640SHAKE", frodo640shake.Scheme()}
)

var _ internal.Scheme = circlScheme{}

type circlScheme struct {
	scheme.String
	scheme circlkem.Scheme
}

func (s circlScheme) Size() int                  { return s.scheme.CiphertextSize() }
func (s circlScheme) SharedSecretSize() int      { return s.scheme.SharedKeySize() }
func (s circlScheme) EncapsulationSeedSize() int { return s.scheme.EncapsulationSeedSize() }
func (s circlScheme) PrivateKeySize() int        { return s.scheme.PrivateKeySize() }
func (s circlScheme) PublicKeySize() int         { return s.scheme.PublicKeySize() }
func (s circlScheme) SeedSize() int              { return s.scheme.SeedSize() }

func (s circlScheme) DeriveKey(seed []byte) (internal.PublicKey, internal.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic(internal.ErrSeedSize)
	}
	pub, priv := s.scheme.DeriveKeyPair(seed)
	pk := circlPubKey{sch: s, pk: pub}
	return pk, circlPrivKey{priv, pk}
}

func (s circlScheme) UnpackPublic(key []byte) (internal.PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, internal.ErrKeySize
	}
	pub, err := s.scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return circlPubKey{sch: s, pk: pub}, nil
}

func (s circlScheme) UnpackPrivate(key []byte) (internal.PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, internal.ErrKeySize
	}
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pk := circlPubKey{sch: s, pk: priv.Public()}
	return circlPrivKey{priv, pk}, nil
}

var _ internal.PrivateKey = circlPrivKey{}

type circlPrivKey struct {
	sk circlkem.PrivateKey
	pk circlPubKey
}

func (priv circlPrivKey) Scheme() internal.Scheme    { return priv.pk.Scheme() }
func (priv circlPrivKey) Public() internal.PublicKey { return priv.pk }

func (priv circlPrivKey) Pack() []byte {
	b, _ := priv.sk.MarshalBinary()
	return b
}

func (priv circlPrivKey) Equal(other internal.PrivateKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPrivKey)
	return ok && priv.sk.Equal(o.sk)
}

func (priv circlPrivKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != priv.pk.sch.Size() {
		return nil, internal.ErrCiphertext
	}
	return priv.sk.Scheme().Decapsulate(priv.sk, ciphertext)
}

var _ internal.PublicKey = (*circlPubKey)(nil)

type circlPubKey struct {
	pk  circlkem.PublicKey
	sch circlScheme
}

func (pub circlPubKey) Scheme() internal.Scheme { return pub.sch }

func (pub circlPubKey) Pack() []byte {
	b, _ := pub.pk.MarshalBinary()
	return b
}

func (pub circlPubKey) Equal(other internal.PublicKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(circlPubKey)
	return ok && pub.pk.Equal(o.pk)
}

func (pub circlPubKey) Encapsulate(seed []byte) (ciphertext, secret []byte, err error) {
	if len(seed) != pub.sch.EncapsulationSeedSize() {
		return nil, nil, internal.ErrEncapsulationSeed
	}
	ct, ss, err := pub.sch.scheme.EncapsulateDeterministically(pub.pk, seed)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}
