package mac

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/karalef/quark/internal"
)

// Scheme represents MAC scheme and provides its parameters.
type Scheme interface {
	Name() string
	Size() int
	BlockSize() int

	// KeySize returns the key size in bytes.
	// If the key size is not fixed, it returns 0.
	KeySize() int
	// MaxKeySize returns the maximum key size in bytes if the key can be length of [1, MaxKeySize()].
	// Returns 0 if the key size is fixed.
	MaxKeySize() int

	// New returns a new MAC instance.
	// Panics if key is not of length KeySize().
	New(key []byte) MAC
}

// Fixed represents a scheme that can fix the key size.
type Fixed interface {
	// Fixed returns the copy of the scheme but with fixed key size.
	// Panics if keySize is invalid.
	Fixed(keySize int) Scheme
}

// NewFunc represents the function to create a MAC.
type NewFunc func(key []byte) MAC

// New creates new MAC scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key length.
func New(name string, keySize, maxKeySize, size, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		new:     new,
		name:    name,
		size:    size,
		block:   blockSize,
		keySize: keySize,
		maxSize: maxKeySize,
	}
}

type baseScheme struct {
	new     NewFunc
	name    string
	size    int
	block   int
	keySize int
	maxSize int
}

func (s baseScheme) Name() string    { return s.name }
func (s baseScheme) Size() int       { return s.size }
func (s baseScheme) BlockSize() int  { return s.block }
func (s baseScheme) KeySize() int    { return s.keySize }
func (s baseScheme) MaxKeySize() int { return s.maxSize }
func (s baseScheme) New(key []byte) MAC {
	if err := CheckKeySize(s, len(key)); err != nil {
		panic(err)
	}
	return s.new(key)
}
func (s baseScheme) Fixed(keySize int) Scheme {
	if err := CheckKeySize(s, keySize); err != nil {
		panic(err)
	}
	s.maxSize = 0
	s.keySize = keySize
	return s
}

// MAC represent MAC state.
type MAC interface {
	// Write never returns an error.
	io.Writer

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte

	// Reset resets the MAC to its initial state.
	Reset()
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(tag1, tag2 []byte) bool {
	return subtle.ConstantTimeCompare(tag1, tag2) == 1
}

// CheckKeySize checks the key size.
func CheckKeySize(s Scheme, size int) error {
	fixed, max := s.KeySize(), s.MaxKeySize()
	switch {
	case fixed == 0 && max == 0:
	case fixed != 0:
		if size != fixed {
			return errors.Join(ErrKeySize, errors.New("does not match fixed key size"))
		}
	default:
		if size > max {
			return errors.Join(ErrKeySize, errors.New("exceeds maximum key size"))
		}
	}
	return nil
}

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

// ErrMismatch is returned when the MACs do not match.
var ErrMismatch = errors.New("MACs do not match")

var schemes = make(internal.Schemes[Scheme])

// Register registers a MAC scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the MAC scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered MAC algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered MAC schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
