package sign

import (
	"github.com/algorand/falcon"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign/stream"
	"github.com/karalef/quark/scheme"
)

// Falcon1024 signature scheme.
var Falcon1024 = falconScheme{scheme.String("Falcon1024")}

func init() {
	Register(Falcon1024)
}

var _ Scheme = falconScheme{}

type falconScheme struct {
	scheme.String
}

const (
	falconSeedSize = 48
	privateKeySize = falcon.PrivateKeySize + falcon.PublicKeySize
)

func (s falconScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	pk := &falconPubKey{crypto.NewKeyID((*falconPublicKey)(&pub))}
	sk := falconPrivateKey{priv, falconPublicKey(pub)}
	return &falconPrivKey{sk, pk}, pk, nil
}

func (s falconScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub := new(falconPublicKey)
	copy(pub[:], key)
	return &falconPubKey{crypto.NewKeyID(pub)}, nil
}

func (s falconScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	priv := &falconPrivKey{}
	copy(priv.PrivateKey[:], key[:falcon.PrivateKeySize])
	copy(priv.falconPublicKey[:], key[falcon.PrivateKeySize:])
	priv.pub = &falconPubKey{crypto.NewKeyID(&priv.falconPublicKey)}
	return priv, nil
}

func (falconScheme) PublicKeySize() int  { return falcon.PublicKeySize }
func (falconScheme) PrivateKeySize() int { return privateKeySize }
func (falconScheme) SignatureSize() int  { return falcon.CTSignatureSize }
func (falconScheme) SeedSize() int       { return falconSeedSize }

type falconPrivateKey struct {
	falcon.PrivateKey
	falconPublicKey
}

func (falconPrivateKey) Scheme() crypto.Scheme { return Falcon1024 }

func (priv *falconPrivateKey) Equal(p *falconPrivateKey) bool {
	if priv == p {
		return true
	}
	if priv == nil || p == nil {
		return false
	}
	return priv.PrivateKey == p.PrivateKey
}

func (priv falconPrivateKey) Pack() []byte {
	out := make([]byte, privateKeySize)
	copy(out[:falcon.PrivateKeySize], priv.PrivateKey[:])
	copy(out[falcon.PrivateKeySize:], priv.falconPublicKey[:])
	return out
}

func (priv *falconPrivateKey) Sign(msg []byte) []byte {
	sig := crypto.OrPanic(priv.SignCompressed(msg))
	ct := crypto.OrPanic(sig.ConvertToCT())
	return ct[:]
}

var _ PrivateKey = (*falconPrivKey)(nil)

type falconPrivKey struct {
	falconPrivateKey
	pub *falconPubKey
}

func (priv *falconPrivKey) ID() crypto.ID                   { return priv.pub.ID() }
func (priv *falconPrivKey) Fingerprint() crypto.Fingerprint { return priv.pub.Fingerprint() }
func (priv *falconPrivKey) Scheme() crypto.Scheme           { return priv.pub.Scheme() }
func (priv *falconPrivKey) Public() PublicKey               { return priv.pub }

func (priv *falconPrivKey) Equal(p PrivateKey) bool {
	if p == nil {
		return false
	}
	pk, ok := p.(*falconPrivKey)
	if !ok {
		return false
	}
	if priv == pk {
		return true
	}
	if priv == nil || pk == nil {
		return false
	}
	return priv.falconPrivateKey.Equal(&pk.falconPrivateKey)
}

func (priv *falconPrivKey) Sign() Signer {
	return stream.StreamSigner(&priv.falconPrivateKey, hash.SHA3_512)
}

type falconPublicKey falcon.PublicKey

func (falconPublicKey) Scheme() crypto.Scheme { return Falcon1024 }
func (pub falconPublicKey) Pack() []byte      { return crypto.Copy(pub[:]) }
func (pub *falconPublicKey) Equal(p *falconPublicKey) bool {
	if pub == p {
		return true
	}
	if pub == nil || p == nil {
		return false
	}
	return *pub == *p
}

func (pub *falconPublicKey) Verify(msg, signature []byte) (bool, error) {
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, err
}

var _ PublicKey = (*falconPubKey)(nil)

type falconPubKey struct {
	crypto.KeyID[*falconPublicKey]
}

func (pub *falconPubKey) Equal(pk PublicKey) bool {
	if pk == nil {
		return false
	}
	p, ok := pk.(*falconPubKey)
	if !ok {
		return false
	}
	if pub == p {
		return true
	}
	if pub == nil || p == nil {
		return false
	}
	return pub.PublicKey.Equal(p.PublicKey)
}

func (pub *falconPubKey) Verify() Verifier {
	return stream.StreamVerifier(pub.PublicKey, hash.SHA3_512)
}
