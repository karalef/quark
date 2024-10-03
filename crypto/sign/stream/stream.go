package stream

import (
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign"
)

// StreamSigner returns a Signer that uses the provided hash function.
// If priv implements StreamPrivateKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamSigner(priv sign.PrivateKey, hash hash.Scheme) sign.Signer {
	if stream, ok := priv.(sign.StreamPrivateKey); ok {
		return stream.Signer()
	}
	if hash == nil {
		hash = NewBuffer(0)
	}
	return &streamSigner{hash.New(), priv}
}

// StreamVerifier returns a Verifier that uses the provided hash function.
// If pub implements StreamPublicKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamVerifier(pub sign.PublicKey, hash hash.Scheme) sign.Verifier {
	if stream, ok := pub.(sign.StreamPublicKey); ok {
		return stream.Verifier()
	}
	if hash == nil {
		hash = NewBuffer(0)
	}
	return &streamVerifier{hash.New(), pub}
}

var _ sign.Signer = (*streamSigner)(nil)

type streamSigner struct {
	hash hash.State
	priv sign.PrivateKey
}

func (s *streamSigner) Write(d []byte) (int, error) { return s.hash.Write(d) }
func (s *streamSigner) Reset()                      { s.hash.Reset() }
func (s *streamSigner) Sign() []byte                { return s.priv.Sign(s.hash.Sum(nil)) }

var _ sign.Verifier = (*streamVerifier)(nil)

type streamVerifier struct {
	hash hash.State
	pub  sign.PublicKey
}

func (v *streamVerifier) Write(d []byte) (int, error) { return v.hash.Write(d) }
func (v *streamVerifier) Reset()                      { v.hash.Reset() }
func (v *streamVerifier) Verify(signature []byte) (bool, error) {
	return v.pub.Verify(v.hash.Sum(nil), signature)
}
