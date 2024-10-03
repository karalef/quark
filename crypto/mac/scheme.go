package mac

import "github.com/karalef/quark/scheme"

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
		StringName: scheme.StringName(name),
		new:        new,
		size:       size,
		block:      blockSize,
		keySize:    keySize,
		maxSize:    maxKeySize,
	}
}

type baseScheme struct {
	scheme.StringName
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

var schemes = make(scheme.Schemes[Scheme])

// Register registers a MAC scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the MAC scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListAll returns all registered MAC algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered MAC schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
