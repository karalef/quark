package hash

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/xof"
)

// NewFromXOF creates new hash scheme from a XOF scheme.
// It does not register the scheme.
func NewFromXOF(scheme xof.Scheme, size int) Scheme {
	return xofScheme{Scheme: scheme, size: size}
}

type xofScheme struct {
	xof.Scheme
	size int
}

func (s xofScheme) Size() int  { return s.size }
func (s xofScheme) New() State { return &xofState{s, s.Scheme.New()} }

type xofState struct {
	scheme xofScheme
	s      xof.State
}

func (s *xofState) Size() int                   { return s.scheme.Size() }
func (s *xofState) BlockSize() int              { return s.scheme.BlockSize() }
func (s *xofState) Reset()                      { s.s.Reset() }
func (s *xofState) Write(p []byte) (int, error) { return s.s.Write(p) }

func (s *xofState) Sum(b []byte) []byte {
	b, tail := crypto.ExtendSlice(b, s.scheme.size)
	s.s.Clone().Read(tail)
	return b
}
