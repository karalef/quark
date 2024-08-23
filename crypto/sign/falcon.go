//go:build !windows
// +build !windows

package sign

import (
	"github.com/algorand/falcon"
	"github.com/karalef/quark/internal"
)

func init() {
	Register(Falcon1024)
}

// Falcon1024 signature scheme.
var Falcon1024 = falconScheme{}

var _ Scheme = falconScheme{}

type falconScheme struct{}

const falconSeedSize = 48
const privateKeySize = falcon.PrivateKeySize + falcon.PublicKeySize

func (s falconScheme) Name() string { return "Falcon1024" }

func (s falconScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	pk, sk := newKeys(&falconPubKey{pub, s}, &falconPrivKey{priv, s})
	return sk, pk, nil
}

func (s falconScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	pub := new(falconPubKey)
	copy(pub[:], key)
	return newPub(pub), nil
}

func (s falconScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv := new(falconPrivKey)
	copy(priv.PrivateKey[:], key[:falcon.PrivateKeySize])
	copy(priv.PublicKey[:], key[falcon.PrivateKeySize:])
	_, sk := newKeys(nil, priv)
	return sk, nil
}

func (falconScheme) PublicKeySize() int  { return falcon.PublicKeySize }
func (falconScheme) PrivateKeySize() int { return privateKeySize }
func (falconScheme) SignatureSize() int  { return falcon.CTSignatureSize }
func (falconScheme) SeedSize() int       { return falconSeedSize }

var _ rawPrivateKey = &falconPrivKey{}
var _ rawPublicKey = &falconPubKey{}

type falconPrivKey struct {
	falcon.PrivateKey
	falcon.PublicKey
}

func (*falconPrivKey) Scheme() Scheme { return falconScheme{} }

func (priv *falconPrivKey) Public() rawPublicKey {
	return (*falconPubKey)(&priv.PublicKey)
}

func (priv *falconPrivKey) Equal(p rawPrivateKey) bool {
	sec, ok := p.(*falconPrivKey)
	return ok && *priv == *sec
}

func (priv *falconPrivKey) Pack() []byte {
	out := make([]byte, privateKeySize)
	copy(out[:falcon.PrivateKeySize], priv.PrivateKey[:])
	copy(out[falcon.PrivateKeySize:], priv.PublicKey[:])
	return out
}

func (priv *falconPrivKey) Sign(msg []byte) []byte {
	sig, err := priv.PrivateKey.SignCompressed(msg)
	if err != nil {
		panic(err)
	}
	ct, err := sig.ConvertToCT()
	if err != nil {
		panic(err)
	}
	return ct[:]
}

type falconPubKey falcon.PublicKey

func (*falconPubKey) Scheme() Scheme { return falconScheme{} }

func (pub *falconPubKey) Equal(p rawPublicKey) bool {
	sec, ok := p.(*falconPubKey)
	return ok && *pub == *sec
}

func (pub *falconPubKey) Pack() []byte {
	return internal.Copy(pub[:])
}

func (pub *falconPubKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != falcon.CTSignatureSize {
		return false, ErrSignature
	}
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, err
}
