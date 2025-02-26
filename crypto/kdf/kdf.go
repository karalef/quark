package kdf

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

// Expander expands a state into a key with length size using the provided info.
type Expander interface {
	Expand(info []byte, length uint) []byte
}

// Extractor represents a scheme with custom extraction phase.
type Extractor[T any] interface {
	Extract(secret T, salt []byte) (Expander, error)
}

// Scheme represents the scheme of key derivation function.
type Scheme interface {
	scheme.Scheme

	// Extract extracts a state from a secret and salt and returns a state
	// expander.
	Extract(secret, salt []byte) Expander

	// Expander returns a state expander for the provided pseudo-random key.
	// The prk must have enough entropy to safety skip the extraction.
	Expander(prk []byte) Expander
}

// errors
var (
	ErrSecret = errors.New("secret is too short")
	ErrSize   = errors.New("invalid key size")
)

// New creates a new Scheme.
// It does not register the scheme.
func New(name string, new func(secret, salt []byte) Expander, exp func(prk []byte) Expander) Scheme {
	return kdf{
		String: scheme.String(name),
		new:    new,
		exp:    exp,
	}
}

type kdf struct {
	scheme.String
	new func(secret, salt []byte) Expander
	exp func(prk []byte) Expander
}

func (s kdf) Extract(secret, salt []byte) Expander { return s.new(secret, salt) }

func (s kdf) Expander(prk []byte) Expander { return s.exp(prk) }

// NewSalted creates a new Salted with random salt of length saltSize.
func NewSalted(kdf Scheme, saltSize uint) Salted {
	salt := crypto.Rand(int(saltSize))
	return Salted{
		Scheme: scheme.NewAlgorithm[Scheme, Registry](kdf),
		Salt:   salt,
	}
}

// Salted contains salt and KDF scheme.
type Salted struct {
	Scheme Algorithm `msgpack:"scheme"`

	// Salt is the salt used for the KDF.
	Salt []byte `msgpack:"salt"`
}

// Extract extracts the KDF state from the secret.
func (s Salted) Extract(secret []byte) Expander { return s.Scheme.Scheme.Extract(secret, s.Salt) }

// Expander returns a state expander for the provided pseudo-random key.
func (s Salted) Expander(prk []byte) Expander { return s.Scheme.Scheme.Expander(prk) }

var kdfs = make(scheme.Map[Scheme])

// Register registers a KDF.
func Register(KDF Scheme) { kdfs.Register(KDF) }

// ByName returns the KDF by the provided name.
func ByName(name string) (Scheme, error) { return kdfs.ByName(name) }

// ListNames returns all registered KDF names.
func ListNames() []string { return kdfs.ListNames() }

// List returns all registered KDF schemes.
func List() []Scheme { return kdfs.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
