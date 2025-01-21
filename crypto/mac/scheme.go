package mac

import (
	"errors"

	"github.com/karalef/quark/scheme"
)

// Scheme represents the MAC scheme.
type Scheme interface {
	scheme.Scheme
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
	New(key []byte) State
}

// NewFunc represents the function to create a MAC.
type NewFunc func(key []byte) State

// New creates new MAC scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key length.
func New(name string, keySize, maxKeySize, size, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		String:  scheme.String(name),
		new:     new,
		size:    size,
		block:   blockSize,
		keySize: keySize,
		maxSize: maxKeySize,
	}
}

// Fixed returns a fixed key size scheme.
// Panics if s is already fixed and keySize is not equal to s.KeySize().
func Fixed(s Scheme, keySize int) Scheme {
	if ks := s.KeySize(); ks != 0 {
		if keySize != ks {
			panic("key size mismatch")
		}
		return s
	}
	if bs, ok := s.(baseScheme); ok {
		bs.keySize = keySize
		return bs
	}
	return fixed{s, keySize}
}

type fixed struct {
	Scheme
	keySize int
}

func (s fixed) KeySize() int { return s.keySize }

type baseScheme struct {
	scheme.String
	new     NewFunc
	size    int
	block   int
	keySize int
	maxSize int
}

func (s baseScheme) Size() int       { return s.size }
func (s baseScheme) BlockSize() int  { return s.block }
func (s baseScheme) KeySize() int    { return s.keySize }
func (s baseScheme) MaxKeySize() int { return s.maxSize }
func (s baseScheme) New(key []byte) State {
	if err := CheckKeySize(s, len(key)); err != nil {
		panic(err)
	}
	return s.new(key)
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

var schemes = make(scheme.Map[Scheme])

// Register registers a MAC scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the MAC scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered MAC algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered MAC schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }
