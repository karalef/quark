package xof

import (
	"encoding/binary"
)

// NewKDF returns a new XOF-based KDF.
func NewKDF(x State) KDF { return KDF{x} }

// KDF is a XOF-based KDF.
type KDF struct{ State }

// Derive derives a key of size length using the underlying state and info.
func (e KDF) Derive(info []byte, length uint) []byte {
	return Derive(e.State, info, length)
}

// Extract returns the XOF state for the provided secret and salt.
func Extract(x Scheme, secret, salt []byte) KDF {
	f := x.New()
	f.Write(salt)
	f.Write(secret)
	return NewKDF(f)
}

// Derive derives a key of size length using the provided state and info.
func Derive(state State, info []byte, length uint) []byte {
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
