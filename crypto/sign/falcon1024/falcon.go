package falcon1024

import (
	"bytes"

	"github.com/algorand/falcon"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign/internal"
	"github.com/karalef/quark/crypto/sign/stream"
)

// Scheme is a falcon1024 signature scheme.
var Scheme internal.Scheme = falconScheme{}

type falconScheme struct{}

func (falconScheme) Name() string { return "Falcon1024" }

const (
	falconSeedSize = 48
	privateKeySize = falcon.PrivateKeySize + falcon.PublicKeySize
)

func (s falconScheme) DeriveKey(seed []byte) (internal.PublicKey, internal.PrivateKey) {
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		panic(internal.ErrSeedSize)
	}
	return s.makeKeys(priv[:], pub[:])
}

func (s falconScheme) UnpackPublic(key []byte) (internal.PublicKey, error) {
	if len(key) != falcon.PublicKeySize {
		return nil, internal.ErrKeySize
	}
	pub := new(falconPubKey)
	copy(pub[:], key)
	return pub, nil
}

func (s falconScheme) UnpackPrivate(key []byte) (internal.PrivateKey, error) {
	if len(key) != privateKeySize {
		return nil, internal.ErrKeySize
	}
	_, sk := s.makeKeys(key[:falcon.PrivateKeySize], key[falcon.PrivateKeySize:])
	return sk, nil
}

func (falconScheme) makeKeys(sk, pk []byte) (internal.PublicKey, internal.PrivateKey) {
	priv := &falconPrivKey{pub: new(falconPubKey)}
	copy(priv.falconPrivateKey[:], sk)
	copy(priv.pub[:], pk)
	return priv.pub, priv
}

func (falconScheme) PublicKeySize() int  { return falcon.PublicKeySize }
func (falconScheme) PrivateKeySize() int { return privateKeySize }
func (falconScheme) SeedSize() int       { return falconSeedSize }
func (falconScheme) Size() int           { return falcon.CTSignatureSize }

type falconPrivateKey falcon.PrivateKey

func (priv *falconPrivateKey) Sign(msg []byte) []byte {
	sig := crypto.OrPanic((*falcon.PrivateKey)(priv).SignCompressed(msg))
	ct := crypto.OrPanic(sig.ConvertToCT())
	return ct[:]
}

var _ internal.PrivateKey = (*falconPrivKey)(nil)

type falconPrivKey struct {
	pub *falconPubKey
	falconPrivateKey
}

func (*falconPrivKey) Scheme() internal.Scheme { return Scheme }

func (priv falconPrivKey) Pack() []byte {
	out := make([]byte, privateKeySize)
	copy(out[:falcon.PrivateKeySize], priv.falconPrivateKey[:])
	copy(out[falcon.PrivateKeySize:], priv.pub[:])
	return out
}

func (priv falconPrivKey) Public() internal.PublicKey { return priv.pub }

func (priv *falconPrivKey) Equal(other internal.PrivateKey) bool {
	if priv == nil || other == nil {
		return false
	}
	o, ok := other.(*falconPrivKey)
	if !ok || o == nil {
		return false
	}
	return priv == o || priv.falconPrivateKey == o.falconPrivateKey
}

func (priv falconPrivKey) Sign() internal.Signer {
	return stream.StreamSigner(&priv.falconPrivateKey, hash.SHA3_512)
}

type falconPublicKey falcon.PublicKey

func (pub *falconPublicKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != falcon.CTSignatureSize {
		return false, internal.ErrSignature
	}
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, nil
}

var _ internal.PublicKey = (*falconPubKey)(nil)

type falconPubKey falconPublicKey

func (*falconPubKey) Scheme() internal.Scheme { return Scheme }

func (pub falconPubKey) Pack() []byte { return bytes.Clone(pub[:]) }

func (pub *falconPubKey) Equal(other internal.PublicKey) bool {
	if pub == nil || other == nil {
		return false
	}
	o, ok := other.(*falconPubKey)
	if !ok || o == nil {
		return false
	}
	return pub == o || *pub == *o
}

func (pub *falconPubKey) Verify() internal.Verifier {
	return stream.StreamVerifier((*falconPublicKey)(pub), hash.SHA3_512)
}
