package sign

import (
	"io"

	"github.com/algorand/falcon"
)

var _ Scheme = falconScheme{}

type falconScheme struct{}

const falconSeedSize = 48

func (falconScheme) GenerateKey(rand io.Reader) (PrivateKey, PublicKey, error) {
	var seed [falconSeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}
	pub, priv, err := falcon.GenerateKey(seed[:])
	if err != nil {
		return nil, nil, err
	}

	p := &falconPrivKey{
		priv: priv,
		pub:  &falconPubKey{pub},
	}
	return p, p.pub, nil
}

func (falconScheme) UnpackPublic(key []byte) (PublicKey, error) {
	pub, err := falcon.UnpackPublic(key)
	if err != nil {
		return nil, err
	}
	p := &falconPubKey{
		pub: pub,
	}
	return p, nil
}

var _ PrivateKey = &falconPrivKey{}
var _ PublicKey = &falconPubKey{}

type falconPrivKey struct {
	priv falcon.PrivateKey
	pub  *falconPubKey
}

func (*falconPrivKey) Scheme() Scheme {
	return falconScheme{}
}

func (priv *falconPrivKey) Public() PublicKey {
	return priv.pub
}

func (priv *falconPrivKey) Pack() ([]byte, error) {
	packed := [falcon.PrivateKeySize]byte(priv.priv)
	return packed[:], nil
}

func (priv *falconPrivKey) Sign(msg []byte) ([]byte, error) {
	sig, err := priv.priv.SignCompressed(msg)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

type falconPubKey struct {
	falcon.PublicKey
}

func (*falconPubKey) Scheme() Scheme {
	return falconScheme{}
}

func (pub *falconPubKey) Pack() ([]byte, error) {
	packed := [falcon.PublicKeySize]byte(pub.PublicKey)
	return packed[:], nil
}

func (pub *falconPubKey) Verify(msg, signature []byte) error {
	if len(signature) != falcon.CTSignatureSize {
		return ErrInvalidSignatureSize
	}
	return pub.PublicKey.VerifyCTSignature(falcon.CTSignature(signature), msg)
}
