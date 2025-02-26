package xof

import (
	"encoding/binary"
)

// NewExtractor returns a new XOF-based crypto.Extractor.
func NewExtractor(x Scheme) Extractor { return Extractor{x} }

// NewExpander returns a new XOF-based crypto.Expander.
func NewExpander(x State) Expander { return Expander{x} }

// Extractor is a XOF-based crypto.Extractor.
type Extractor struct{ Scheme }

// Extract implements crypto.Extractor.
func (e Extractor) Extract(salt, secret []byte) Expander {
	return Expander{Extract(e.Scheme, secret, salt)}
}

// Expander is a XOF-based crypto.Expander.
type Expander struct{ State }

// Expand implements crypto.Expander.
func (e Expander) Expand(info []byte, length uint) []byte {
	return Expand(e.State, info, length)
}

// Extract returns the XOF state for the provided secret and salt.
func Extract(x Scheme, secret, salt []byte) Expander {
	f := x.New()
	f.Write(salt)
	f.Write(secret)
	return NewExpander(f)
}

// Expand returns a derived key of size length using the provided hmac,
// pseudo-random key and info.
func Expand(state State, info []byte, length uint) []byte {
	if length == 0 {
		panic("invalid key size")
	}
	var kLen [8]byte
	binary.BigEndian.PutUint64(kLen[:], uint64(length))
	out := make([]byte, length)
	x := state.Clone()
	x.Write(kLen[:])
	x.Write(info)
	x.Read(out)
	return out
}
