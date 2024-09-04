package kdf

import (
	"errors"

	"github.com/karalef/quark/internal"
)

// Scheme represents the key derivation function.
type Scheme interface {
	internal.Scheme

	// New creates a new KDF.
	New(Cost) (KDF, error)
}

// KDF represents the key derivation function.
type KDF interface {
	Cost() Cost
	// Derive derives a key of the specified size from a password and salt.
	// Panics if size is zero.
	Derive(password, salt []byte, size int) []byte
}

// Cost represents the key derivation function cost parameters.
type Cost struct {
	CPU         uint `msgpack:"cpu"`
	Memory      uint `msgpack:"memory"`
	Parallelism uint `msgpack:"parallelism"`
}

// ErrPassword is returned when the password is empty.
var ErrPassword = errors.New("kdf: empty password")

// ErrInvalidParams is returned when the parameters are invalid.
type ErrInvalidParams struct {
	KDF Scheme
	Err error
}

func (e ErrInvalidParams) Error() string {
	return "kdf: invalid " + e.KDF.Name() + " parameters: " + e.Err.Error()
}

// Func represents the KDF as function.
type Func func(password, salt []byte, size int, cost Cost) []byte

// FuncCost represents the Cost validator function.
type FuncCost func(Cost) error

// New creates a new scheme.
// It does not register the scheme.
// The returned scheme ensures that the size are at least 1 and the Cost is correct.
func New(name string, fn Func, cost FuncCost) Scheme {
	return baseScheme{
		name:   name,
		cost:   cost,
		derive: fn,
	}
}

type baseScheme struct {
	name   string
	cost   FuncCost
	derive Func
}

func (s baseScheme) Name() string { return s.name }

func (s baseScheme) New(cost Cost) (KDF, error) {
	err := s.cost(cost)
	if err != nil {
		return nil, err
	}
	return baseKDF{
		kdf:  s.derive,
		cost: cost,
	}, nil
}

type baseKDF struct {
	cost Cost
	kdf  Func
}

func (kdf baseKDF) Cost() Cost { return kdf.cost }

func (kdf baseKDF) Derive(password, salt []byte, size int) []byte {
	if size < 1 {
		panic("kdf: size must be at least 1")
	}
	return kdf.kdf(password, salt, size, kdf.cost)
}

var kdfs = make(internal.Schemes[Scheme])

// Register registers a KDF.
func Register(kdf Scheme) { kdfs.Register(kdf) }

// ByName returns the KDF by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return kdfs.ByName(name) }

// ListAll returns all registered KDF algorithms.
func ListAll() []string { return kdfs.ListAll() }

// ListSchemes returns all registered KDF schemes.
func ListSchemes() []Scheme { return kdfs.ListSchemes() }
