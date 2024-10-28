package kdf

import (
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/xof"
)

// NoCost is used for not configurable KDFs.
type NoCost struct{}

func (*NoCost) New() Cost       { return new(NoCost) }
func (*NoCost) Validate() error { return nil }

// FromHash creates a new Scheme from a hash scheme.
// The scheme will accept only the output size equal to hash size.
// The Cost will be NoCost.
//
//nolint:errcheck
func FromHash(h hash.Scheme) Scheme {
	return New(h.Name(), func(password, salt []byte, _ uint32, _ *NoCost) []byte {
		s := h.New()
		s.Write(salt)
		s.Write(password)
		return s.Sum(nil)
	})
}

// FromHash creates a new Scheme from a XOF scheme.
// The Cost will be NoCost.
//
//nolint:errcheck
func FromXOF(xof xof.Scheme) Scheme {
	return New(xof.Name(), func(password, salt []byte, size uint32, _ *NoCost) []byte {
		s := xof.New()
		s.Write(salt)
		s.Write(password)

		key := make([]byte, size)
		s.Read(key)
		return key
	})
}
