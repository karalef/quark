package kdf

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// KDF derives a key with length size using the provided info.
type KDF interface {
	Derive(info []byte, length uint) []byte
}

// Scheme represents the scheme of key derivation function.
type Scheme interface {
	scheme.Scheme

	// New creates a KDF from a master key. The input must have enough entropy.
	New(masterKey []byte) KDF
}

// ErrShort is returned when the input is too short.
var ErrShort = errors.New("input is too short")

// MinSize is the minimum size of the input.
const MinSize = 16

// New creates a new Scheme.
// It does not register the scheme.
func New(name string, new func([]byte) KDF) Scheme {
	return kdf{
		String: scheme.String(name),
		new:    new,
	}
}

type kdf struct {
	scheme.String
	new func([]byte) KDF
}

func (s kdf) New(in []byte) KDF {
	if len(in) < MinSize {
		panic(ErrShort)
	}
	return s.new(in)
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
