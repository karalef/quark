package block

import (
	stdcipher "crypto/cipher"
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

// Cipher represents a block cipher.
type Cipher = stdcipher.Block

// Scheme type.
type Scheme interface {
	scheme.Scheme

	KeySize() int

	// BlockSize returns the block size.
	BlockSize() int

	// New creates a new cipher.
	// Panics if the key length is wrong.
	New(key []byte) Cipher
}

// NewFunc represents the function to create a stream cipher.
type NewFunc func(key []byte) Cipher

// New creates new block cipher scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key length that are passed to the
// new.
func New(name string, keySize, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		String:    scheme.String(name),
		keySize:   keySize,
		blockSize: blockSize,
		newFunc:   new,
	}
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	scheme.String
	newFunc   NewFunc
	keySize   int
	blockSize int
}

func (s baseScheme) KeySize() int   { return s.keySize }
func (s baseScheme) BlockSize() int { return s.blockSize }

func (s baseScheme) New(key []byte) Cipher {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	return s.newFunc(key)
}

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

var schemes = make(scheme.Map[Scheme])

// Register registers a cipher scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the cipher scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered cipher algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered cipher schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }
