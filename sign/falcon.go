package sign

import (
	"crypto/rand"
	"io"

	"github.com/algorand/falcon"
)

var falcon1024Scheme Scheme = falconScheme{}

type falconScheme struct{}

const falconSeedSize = 48

func (falconScheme) Alg() Algorithm { return Falcon1024 }

func (s falconScheme) GenerateKey() (PrivateKey, PublicKey, error) {
	var seed [falconSeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, nil, err
	}
	return s.derive(seed[:])
}

func (s falconScheme) derive(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrInvalidSeedSize
	}
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	return (*falconPrivKey)(&priv), (*falconPubKey)(&pub), nil
}

func (s falconScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey) {
	priv, pub, err := s.derive(seed)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func (s falconScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrInvalidKeySize
	}
	pub := new(falconPubKey)
	copy(pub[:], key)
	return pub, nil
}

func (s falconScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrInvalidKeySize
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

func (*falconPrivKey) Scheme() Scheme { return falcon1024Scheme }

func (priv *falconPrivKey) Equal(p PrivateKey) bool {
	sec, ok := p.(*falconPrivKey)
	return ok && *priv == *sec
}

func (priv *falconPrivKey) Bytes() []byte {
	cp := *priv
	return cp[:]
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

func (*falconPubKey) Scheme() Scheme { return falcon1024Scheme }

func (pub *falconPubKey) Equal(p PublicKey) bool {
	sec, ok := p.(*falconPubKey)
	return ok && *pub == *sec
}

func (pub *falconPubKey) Bytes() []byte {
	cp := *pub
	return cp[:]
}

func (pub *falconPubKey) Verify(msg, signature []byte) (bool, error) {
	if len(signature) != falcon.CTSignatureSize {
		return false, falcon.ErrVerifyFail
	}
	err := (*falcon.PublicKey)(pub).VerifyCTSignature(falcon.CTSignature(signature), msg)
	return err == nil, nil
}
