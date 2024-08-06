package sign

import "hash"

// StreamSigner returns a Signer that uses the provided hash function.
// If priv implements StreamPrivateKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamSigner(priv PrivateKey, hash func() hash.Hash) Signer {
	if stream, ok := priv.(StreamPrivateKey); ok {
		return stream.Signer()
	}
	if hash == nil {
		hash = newBuffer
	}
	return &streamSigner{hash(), priv}
}

// StreamVerifier returns a Verifier that uses the provided hash function.
// If pub implements StreamPublicKey, the hash function is ignored.
// If hash is nil, uses the bytes buffer to provide streaming.
func StreamVerifier(pub PublicKey, hash func() hash.Hash) Verifier {
	if stream, ok := pub.(StreamPublicKey); ok {
		return stream.Verifier()
	}
	if hash == nil {
		hash = newBuffer
	}
	return &streamVerifier{hash(), pub}
}

var _ Signer = (*streamSigner)(nil)

type streamSigner struct {
	hash hash.Hash
	priv PrivateKey
}

func (s *streamSigner) Write(d []byte) (int, error) { return s.hash.Write(d) }
func (s *streamSigner) Reset()                      { s.hash.Reset() }
func (s *streamSigner) Sign() []byte                { return s.priv.Sign(s.hash.Sum(nil)) }

var _ Verifier = (*streamVerifier)(nil)

type streamVerifier struct {
	hash hash.Hash
	pub  PublicKey
}

func (v *streamVerifier) Write(d []byte) (int, error) { return v.hash.Write(d) }
func (v *streamVerifier) Reset()                      { v.hash.Reset() }
func (v *streamVerifier) Verify(signature []byte) (bool, error) {
	return v.pub.Verify(v.hash.Sum(nil), signature)
}

func newBuffer() hash.Hash {
	b := make([]byte, 0, 512)
	return (*buffer)(&b)
}

type buffer []byte

func (b *buffer) Write(p []byte) (n int, err error) {
	*b = append(*b, p...)
	return len(p), nil
}

func (b *buffer) Reset()              { *b = (*b)[:0] }
func (b *buffer) Sum(s []byte) []byte { return append(s, *b...) }
func (b *buffer) Size() int           { return -1 }
func (b *buffer) BlockSize() int      { return -1 }
