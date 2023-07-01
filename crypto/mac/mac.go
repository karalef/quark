package mac

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/karalef/quark/crypto/internal"
)

// Scheme represents MAC scheme and provides its parameters.
type Scheme interface {
	Name() string
	Size() int
	KeySize() int

	// New returns a new MAC instance.
	// Panics if key is not of length KeySize().
	New(key []byte) MAC
}

type baseScheme struct {
	new     func(key []byte) MAC
	name    string
	size    int
	keySize int
}

func (s baseScheme) Name() string { return s.name }
func (s baseScheme) Size() int    { return s.size }
func (s baseScheme) KeySize() int { return s.keySize }
func (s baseScheme) New(key []byte) MAC {
	if len(key) != s.keySize {
		panic(ErrKeySize)
	}
	return s.new(key)
}

// MAC represent MAC state.
type MAC interface {
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

var schemes = make(internal.Schemes[Scheme])

func init() {
	Register(SHA256)
	Register(SHA3_256)
	Register(BLAKE2b128)
	Register(BLAKE2b128X)
	Register(BLAKE2b256)
}

// Register registers a MAC scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the MAC scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }
