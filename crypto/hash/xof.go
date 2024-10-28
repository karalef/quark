package hash

import (
	"github.com/karalef/quark/crypto/xof"
)

// NewFromXOF creates new hash scheme from a XOF scheme.
// It does not register the scheme.
func NewFromXOF(scheme xof.Scheme, size int) Scheme {
	return xofScheme{Scheme: scheme, size: size}
}

// shake
var (
	// Shake128 is a SHAKE128 with 32 bytes output.
	Shake128 = NewFromXOF(xof.Shake128, 32)

	// Shake256 is a SHAKE256 with 64 bytes output.
	Shake256 = NewFromXOF(xof.Shake256, 64)
)

func init() {
	Register(Shake128)
	Register(Shake256)
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
	top := len(b) + s.scheme.size
	if cap(b) < top {
		newb := make([]byte, len(b), top)
		copy(newb, b)
		b = newb
	}
	res := b[len(b):top]
	s.s.Clone().Read(res)
	return b[:top]
}
