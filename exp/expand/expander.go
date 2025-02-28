package expand

import (
	"github.com/karalef/quark/scheme"
)

// Expander expands a state into a key with length size using the provided material.
type Expander interface {
	Expand(material []byte, length uint) []byte
}

// Scheme is the key expander scheme.
type Scheme interface {
	scheme.Scheme

	// New initialize the expander with context.
	New(context string) Expander
}

var schemes = make(scheme.Map[Scheme])

// Register registers a Scheme.
func Register(sch Scheme) { schemes.Register(sch) }

// ByName returns the Scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered names.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
