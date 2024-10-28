package stream

import (
	"github.com/karalef/quark/crypto/hash"
)

// StreamSigner returns a Signer that uses the provided hash function.
// If priv implements StreamPrivateKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamSigner(priv PrivateKey, hash hash.Scheme) *Signer {
	if hash == nil {
		hash = NewBuffer(0)
	}
	return &Signer{hash.New(), priv}
}

// StreamVerifier returns a Verifier that uses the provided hash function.
// If pub implements StreamPublicKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamVerifier(pub PublicKey, hash hash.Scheme) *Verifier {
	if hash == nil {
		hash = NewBuffer(0)
	}
	return &Verifier{hash.New(), pub}
}

type PrivateKey interface {
	Sign(msg []byte) []byte
}

type Signer struct {
	hash hash.State
	priv PrivateKey
}

func (s *Signer) Write(d []byte) (int, error) { return s.hash.Write(d) }
func (s *Signer) Reset()                      { s.hash.Reset() }
func (s *Signer) Sign() []byte                { return s.priv.Sign(s.hash.Sum(nil)) }

type PublicKey interface {
	Verify(msg []byte, signature []byte) (bool, error)
}

type Verifier struct {
	hash hash.State
	pub  PublicKey
}

func (v *Verifier) Write(d []byte) (int, error) { return v.hash.Write(d) }
func (v *Verifier) Reset()                      { v.hash.Reset() }
func (v *Verifier) Verify(signature []byte) (bool, error) {
	return v.pub.Verify(v.hash.Sum(nil), signature)
}
