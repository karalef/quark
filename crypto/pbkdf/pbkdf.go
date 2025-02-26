package pbkdf

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// Scheme represents the password-based key derivation function.
type Scheme interface {
	scheme.Scheme

	// NewCost allocates a new typed Cost for this function and returns a pointer.
	NewCost() Cost

	// New creates a new PBKDF.
	// Panics if the cost parameter has invalid type.
	// Returns an error if the cost parameters are invalid for this scheme.
	New(Cost) (PBKDF, error)
}

// Derive is an alias for Scheme.New and PBKDF.Derive.
func Derive(s Scheme, c Cost, password []byte, salt []byte, size int) ([]byte, error) {
	kdf, err := s.New(c)
	if err != nil {
		return nil, err
	}
	return kdf.Derive(password, salt, uint32(size)), nil
}

// PBKDF represents the password-based key derivation function.
type PBKDF interface {
	// Derive derives a key of the specified size from a password and salt.
	// Panics if size is zero.
	Derive(password, salt []byte, size uint32) []byte
}

// Cost represents the password-based key derivation function computation cost
// parameters.
//
// It must be msgpack en/decodable.
type Cost interface {
	// Validate validates the cost parameters.
	Validate() error

	// New allocates a new typed Cost and returns a pointer.
	New() Cost
}

// ErrPassword is returned when the password is empty.
var ErrPassword = errors.New("pbkdf: empty password")

// ErrInvalidParams is returned when the parameters are invalid.
type ErrInvalidParams struct {
	KDF Scheme
	Err error
}

func (e ErrInvalidParams) Error() string {
	return "pbkdf: invalid " + e.KDF.Name() + " parameters: " + e.Err.Error()
}

// Func represents the PBKDF as function.
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

func (s baseScheme[T]) New(cost Cost) (PBKDF, error) {
	c, ok := cost.(T)
	if !ok {
		panic(ErrInvalidParams{
			KDF: s,
			Err: errors.New("kdf: wrong cost type"),
		})
	}
	if err := c.Validate(); err != nil {
		return nil, ErrInvalidParams{
			KDF: s,
			Err: err,
		}
	}
	return base[T]{
		derive: s.derive,
		cost:   c,
	}, nil
}

type base[T Cost] struct {
	cost   T
	derive Func[T]
}

func (pbkdf base[T]) Derive(password, salt []byte, size uint32) []byte {
	if size < 1 {
		panic("pbkdf: size must be at least 1")
	}
	return pbkdf.derive(password, salt, size, pbkdf.cost)
}

var pbkdfs = make(scheme.Map[Scheme])

// Register registers a PBKDF.
func Register(pbkdf Scheme) { pbkdfs.Register(pbkdf) }

// ByName returns the PBKDF by the provided name.
func ByName(name string) (Scheme, error) { return pbkdfs.ByName(name) }

// ListNames returns all registered PBKDF algorithms.
func ListNames() []string { return pbkdfs.ListNames() }

// List returns all registered PBKDF schemes.
func List() []Scheme { return pbkdfs.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
