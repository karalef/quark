package sign

import (
	"github.com/algorand/falcon"
	"github.com/karalef/quark/internal"
)

// Falcon1024 returns the Falcon1024 signature scheme.
func Falcon1024() Scheme { return falconScheme{} }

type falconScheme struct{}

const falconSeedSize = 48

func (s falconScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	return (*falconPrivKey)(&priv), (*falconPubKey)(&pub), nil
}

func (s falconScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	pub := new(falconPubKey)
	copy(pub[:], key)
	return pub, nil
}

func (s falconScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv := new(falconPrivKey)
	copy(priv[:], key)
	return priv, nil
}

func (falconScheme) PublicKeySize() int  { return falcon.PublicKeySize }
func (falconScheme) PrivateKeySize() int { return falcon.PrivateKeySize }
func (falconScheme) SignatureSize() int  { return falcon.CTSignatureSize }
func (falconScheme) SeedSize() int       { return falconSeedSize }

var _ PrivateKey = &falconPrivKey{}
var _ PublicKey = &falconPubKey{}

type falconPrivKey falcon.PrivateKey

func (*falconPrivKey) Scheme() Scheme { return falconScheme{} }

func (priv *falconPrivKey) Equal(p PrivateKey) bool {
	sec, ok := p.(*falconPrivKey)
	return ok && *priv == *sec
}

func (priv *falconPrivKey) Bytes() []byte {
	return internal.Copy(priv[:])
}

func (priv *falconPrivKey) Sign(msg []byte) ([]byte, error) {
	sig, err := (*falcon.PrivateKey)(priv).SignCompressed(msg)
	if err != nil {
		return nil, err
	}
	ct, err := sig.ConvertToCT()
	return ct[:], err
}

type falconPubKey falcon.PublicKey

func (*falconPubKey) Scheme() Scheme { return falconScheme{} }

func (pub *falconPubKey) Equal(p PublicKey) bool {
	sec, ok := p.(*falconPubKey)
	return ok && *pub == *sec
}

func (pub *falconPubKey) Bytes() []byte {
	return internal.Copy(pub[:])
}

func (pub *falconPubKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != falcon.CTSignatureSize {
		return false, ErrSignature
	}
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, nil
}
