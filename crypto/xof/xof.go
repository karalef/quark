package xof

import (
	"io"

	"github.com/karalef/quark/scheme"
)

// Scheme represents the scheme of hash function with arbitrary-length output.
type Scheme interface {
	scheme.Scheme
	New() State
	BlockSize() int
}

// State represents the state of hash function with arbitrary-length output.
type State interface {
	// Write absorbs more data into the XOF's state. It panics if called
	// after Read.
	io.Writer

	// Read reads more output from the XOF. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() State

	// Reset restores the XOF to its initial state and discards all data appended by Write.
	Reset()
}

// New creates a new Scheme.
// It does not register the scheme.
func New(name string, bs int, new func() State) Scheme {
	return xof{
		String: scheme.String(name),
		new:    new,
	}
}

type xof struct {
	scheme.String
	new func() State
	bs  int
}

func (s xof) New() State     { return s.new() }
func (s xof) BlockSize() int { return s.bs }

// Schemes is a registry of XOF schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
