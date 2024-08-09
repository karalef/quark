package kdf

import (
	"errors"

	"github.com/karalef/quark/internal"
)

// KDF represents the key derivation function.
type KDF interface {
	Name() string

	// NewParams creates a new key derivation function parameters.
	NewParams() Params

	// Derive derives a key of the specified size from a password and salt.
	// Panics if size is zero.
	Derive(password, salt []byte, size int, params Params) ([]byte, error)
}

// Params represents the key derivation function parameters.
type Params interface {
	Validate() error
	Encode() []byte
	Decode([]byte) error

	new() Params
}

// ErrPassword is returned when the password is empty.
var ErrPassword = errors.New("kdf: empty password")

// ErrInvalidParams is returned when the parameters are invalid.
type ErrInvalidParams struct {
	KDF KDF
	Err error
}

func (e ErrInvalidParams) Error() string {
	return "kdf: invalid " + e.KDF.Name() + " parameters: " + e.Err.Error()
}

// Func represents the KDF as function.
type Func[T Params] func(password, salt []byte, size int, params T) ([]byte, error)

// New creates a new KDF.
// It does not register the KDF.
// The returned KDF ensures that the password length and size are at least 1
// and that the Params is correct.
func New[T Params](name string, fn Func[T]) KDF {
	return baseKDF[T]{
		kdf:  fn,
		name: name,
	}
}

type baseKDF[T Params] struct {
	kdf  func(password, salt []byte, size int, params T) ([]byte, error)
	name string
}

func (kdf baseKDF[T]) NewParams() Params {
	var a T
	return a.new()
}

func (kdf baseKDF[T]) Name() string { return kdf.name }

func (kdf baseKDF[T]) Derive(password, salt []byte, size int, params Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrPassword
	}
	if size < 1 {
		panic("kdf: size must be at least 1")
	}
	p, ok := params.(T)
	if !ok {
		return nil, ErrInvalidParams{
			Err: errors.New("type of Params does not match the KDF"),
		}
	}
	err := p.Validate()
	if err != nil {
		return nil, ErrInvalidParams{
			Err: err,
		}
	}
	return kdf.kdf(password, salt, size, p)
}

var kdfs = make(internal.Schemes[KDF])

// Register registers a KDF.
func Register(kdf KDF) { kdfs.Register(kdf) }

// ByName returns the KDF by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) KDF { return kdfs.ByName(name) }

// ListAll returns all registered KDF algorithms.
func ListAll() []string { return kdfs.ListAll() }

// ListSchemes returns all registered KDF schemes.
func ListSchemes() []KDF { return kdfs.ListSchemes() }
