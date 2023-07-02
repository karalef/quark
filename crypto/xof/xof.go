package xof

import (
	"io"

	"github.com/karalef/quark/crypto/internal"
)

// XOF represents the hash function with arbitrary-length output.
type XOF interface {
	Name() string
	New() State
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

type scheme struct {
	new  func() State
	name string
}

func (s scheme) Name() string { return s.name }
func (s scheme) New() State   { return s.new() }

var xofs = make(internal.Schemes[XOF])

func init() {
	Register(BLAKE2xb)
	Register(BLAKE3x)
	Register(Shake128)
	Register(Shake256)
}

// Register registers a XOF.
func Register(xof XOF) { xofs.Register(xof) }

// ByName returns the XOF by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) XOF { return xofs.ByName(name) }

// ListAll returns all registered XOF names.
func ListAll() []string { return xofs.ListAll() }

// ListSchemes returns all registered XOF schemes.
func ListSchemes() []XOF { return xofs.ListSchemes() }
