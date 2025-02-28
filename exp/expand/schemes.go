package expand

import (
	"github.com/zeebo/blake3"
)

func init() {
	Register(BLAKE3)
}

// BLAKE3 is the BLAKE3 with key derivation flag scheme.
var BLAKE3 = blake3scheme{}

type blake3scheme struct{}

func (blake3scheme) Name() string { return "BLAKE3" }

func (blake3scheme) New(context string) Expander {
	return blake3exp{blake3.NewDeriveKey(context)}
}

type blake3exp struct{ *blake3.Hasher }

func (b blake3exp) Expand(material []byte, len uint) []byte {
	b.Reset()
	dst := make([]byte, len)
	_, _ = b.Write(material)
	_, _ = b.Digest().Read(dst)
	return dst
}
