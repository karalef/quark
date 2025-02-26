package falcon1024

import (
	"bytes"

	"github.com/algorand/falcon"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/sign/stream"
)

// Scheme is a falcon1024 signature scheme.
var Scheme sign.Scheme = falconScheme{}

type falconScheme struct{}

func (falconScheme) Name() string { return "Falcon1024" }

const (
	falconSeedSize = 48
	privateKeySize = falcon.PrivateKeySize + falcon.PublicKeySize
)

func (s falconScheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		panic(sign.ErrSeedSize)
	}
	return s.makeKeys(priv[:], pub[:])
}

func (s falconScheme) UnpackPublic(key []byte) (sign.PublicKey, error) {
	if len(key) != falcon.PublicKeySize {
		return nil, sign.ErrKeySize
	}
	pub := new(falconPubKey)
	copy(pub[:], key)
	return pub, nil
}

func (s falconScheme) UnpackPrivate(key []byte) (sign.PrivateKey, error) {
	if len(key) != privateKeySize {
		return nil, sign.ErrKeySize
	}
	_, sk := s.makeKeys(key[:falcon.PrivateKeySize], key[falcon.PrivateKeySize:])
	return sk, nil
}

func (falconScheme) makeKeys(sk, pk []byte) (sign.PublicKey, sign.PrivateKey) {
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

var _ sign.PrivateKey = (*falconPrivKey)(nil)

type falconPrivKey struct {
	pub *falconPubKey
	falconPrivateKey
}

func (*falconPrivKey) Scheme() sign.Scheme { return Scheme }

func (priv falconPrivKey) Pack() []byte {
	out := make([]byte, privateKeySize)
	copy(out[:falcon.PrivateKeySize], priv.falconPrivateKey[:])
	copy(out[falcon.PrivateKeySize:], priv.pub[:])
	return out
}

func (priv falconPrivKey) Public() sign.PublicKey { return priv.pub }

func (priv *falconPrivKey) Equal(other sign.PrivateKey) bool {
	if priv == nil || other == nil {
		return false
	}
	o, ok := other.(*falconPrivKey)
	if !ok || o == nil {
		return false
	}
	return priv == o || priv.falconPrivateKey == o.falconPrivateKey
}

func (priv falconPrivKey) Sign() sign.Signer {
	return stream.StreamSigner(&priv.falconPrivateKey, hash.SHA3_512)
}

type falconPublicKey falcon.PublicKey

func (pub *falconPublicKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != falcon.CTSignatureSize {
		return false, sign.ErrSignature
	}
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, nil
}

var _ sign.PublicKey = (*falconPubKey)(nil)

type falconPubKey falconPublicKey

func (*falconPubKey) Scheme() sign.Scheme { return Scheme }

func (pub falconPubKey) Pack() []byte { return bytes.Clone(pub[:]) }

func (pub *falconPubKey) Equal(other sign.PublicKey) bool {
	if pub == nil || other == nil {
		return false
	}
	o, ok := other.(*falconPubKey)
	if !ok || o == nil {
		return false
	}
	return pub == o || *pub == *o
}

func (pub *falconPubKey) Verify() sign.Verifier {
	return stream.StreamVerifier((*falconPublicKey)(pub), hash.SHA3_512)
}
