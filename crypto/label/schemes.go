package label

import (
	"github.com/karalef/quark/crypto/mac"
	"github.com/zeebo/blake3"
)

func init() {
	Register(BLAKE3)
	Register(HKDF_SHA3)
}

// BLAKE3 is the BLAKE3 with key derivation flag scheme.
var BLAKE3 = blake3scheme{}

// HKDF_SHA3 is the HKDF that uses SHA3 as the hash function.
var HKDF_SHA3 = hmacScheme{mac.SHA3}

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

type hmacScheme struct{ mac.Scheme }

func (s hmacScheme) New(context string) Expander {
	return hmacExp{ctx: []byte(context), Scheme: s.Scheme}
}

type hmacExp struct {
	ctx []byte
	mac.Scheme
}

func (h hmacExp) Expand(material []byte, len uint) []byte {
	return mac.Expand(h.Scheme, material, h.ctx, len)
}
