package kdf

import "github.com/karalef/quark/scheme"

// KDF derives a key with length size using the provided info.
type KDF interface {
	Derive(info []byte, length uint) []byte
}

// Scheme represents the scheme of key derivation function.
type Scheme interface {
	scheme.Scheme

	// New creates a KDF from an input key material.
	New(ikm, salt []byte) KDF
}

// New creates a new Scheme.
// It does not register the scheme.
func New(name string, new func([]byte, []byte) KDF) Scheme {
	return kdf{
		String: scheme.String(name),
		new:    new,
	}
}

type kdf struct {
	scheme.String
	new func([]byte, []byte) KDF
}

func (s kdf) New(ikm, salt []byte) KDF { return s.new(ikm, salt) }

// Schemes is a registry of KDF schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
