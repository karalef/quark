package kdf

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// Scheme represents the key derivation function.
type Scheme interface {
	scheme.Scheme

	// NewCost allocates a new typed Cost for this function and returns a pointer.
	NewCost() Cost

	// New creates a new KDF.
	// Returns an error if the cost parameters are invalid for this scheme.
	New(Cost) (KDF, error)
}

// Derive is an alias for Scheme.New and KDF.Derive.
func Derive(s Scheme, c Cost, password string, salt []byte, size int) ([]byte, error) {
	kdf, err := s.New(c)
	if err != nil {
		return nil, err
	}
	return kdf.Derive([]byte(password), salt, uint32(size)), nil
}

// KDF represents the key derivation function.
type KDF interface {
	Cost() Cost
	// Derive derives a key of the specified size from a password and salt.
	// Panics if size is zero.
	Derive(password, salt []byte, size uint32) []byte
}

// Cost represents the key derivation function cost parameters.
// It must be msgpack en/decodable.
type Cost interface {
	Validate() error

	// New allocates a new typed Cost and returns a pointer.
	New() Cost
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
type Func[T Cost] func(password, salt []byte, size uint32, cost T) []byte

// New creates a new scheme.
// It does not register the scheme.
// The returned scheme ensures that the size are at least 1 and the Cost is correct.
func New[T Cost](name string, fn Func[T]) Scheme {
	return baseScheme[T]{
		String: scheme.String(name),
		derive: fn,
	}
}

type baseScheme[T Cost] struct {
	derive Func[T]
	scheme.String
}

func (s baseScheme[T]) NewCost() Cost {
	var c T
	return c.New()
}

func (s baseScheme[T]) New(cost Cost) (KDF, error) {
	c, ok := cost.(T)
	if !ok {
		return nil, ErrInvalidParams{
			KDF: s,
			Err: errors.New("kdf: wrong cost type"),
		}
	}
	if err := c.Validate(); err != nil {
		return nil, ErrInvalidParams{
			KDF: s,
			Err: err,
		}
	}
	return baseKDF[T]{
		kdf:  s.derive,
		cost: c,
	}, nil
}

type baseKDF[T Cost] struct {
	cost T
	kdf  Func[T]
}

func (kdf baseKDF[T]) Cost() Cost { return kdf.cost }

func (kdf baseKDF[T]) Derive(password, salt []byte, size uint32) []byte {
	if size < 1 {
		panic("kdf: size must be at least 1")
	}
	return kdf.kdf(password, salt, size, kdf.cost)
}

var kdfs = make(scheme.Map[Scheme])

// Register registers a KDF.
func Register(kdf Scheme) { kdfs.Register(kdf) }

// ByName returns the KDF by the provided name.
func ByName(name string) (Scheme, error) { return kdfs.ByName(name) }

// ListNames returns all registered KDF algorithms.
func ListNames() []string { return kdfs.ListNames() }

// List returns all registered KDF schemes.
func List() []Scheme { return kdfs.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }
