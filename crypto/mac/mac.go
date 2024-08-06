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
	// MaxKeySize returns the maximum key size in bytes if the key can be length of 1-MaxKeySize().
	// Returns 0 if the key size is fixed.
	MaxKeySize() int

	// New returns a new MAC instance.
	// Panics if key is not of length KeySize().
	New(key []byte) MAC
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
	if len(key) == 0 ||
		s.keySize != 0 && len(key) != s.keySize ||
		s.maxSize != 0 && len(key) > s.maxSize {
		panic(ErrKeySize)
	}
	return s.new(key)
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

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

// ErrMismatch is returned when the MACs do not match.
var ErrMismatch = errors.New("MACs do not match")

var schemes = make(internal.Schemes[Scheme])

func init() {
	Register(SHA256)
	Register(SHA3_256)
	Register(BLAKE2b128)
	Register(BLAKE2b256)
	Register(BLAKE3)
}

// Register registers a MAC scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the MAC scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered MAC algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered MAC schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
