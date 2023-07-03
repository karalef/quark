package cipher

import (
	stdcipher "crypto/cipher"
	"errors"

	"github.com/karalef/quark/crypto/internal"
)

// Stream represents a stream cipher.
type Stream = stdcipher.Stream

// Scheme type.
type Scheme interface {
	Name() string

	KeySize() int
	IVSize() int

	New(key, iv []byte) (Stream, error)
}

// NewFunc represents the function to create a stream cipher.
type NewFunc func(key, iv []byte) (Stream, error)

// New creates new cipher scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key and iv lengths
// that are passed to the new.
func New(name string, keySize, ivSize int, new NewFunc) Scheme {
	return baseScheme{
		name:    name,
		keySize: keySize,
		ivSize:  ivSize,
		newFunc: new,
	}
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	newFunc NewFunc
	name    string
	keySize int
	ivSize  int
}

func (s baseScheme) Name() string { return s.name }
func (s baseScheme) KeySize() int { return s.keySize }
func (s baseScheme) IVSize() int  { return s.ivSize }
func (s baseScheme) New(key, iv []byte) (Stream, error) {
	if len(key) != s.keySize {
		return nil, ErrKeySize
	}
	if len(iv) != s.ivSize {
		return nil, ErrIVSize
	}
	return s.newFunc(key, iv)
}

// errors
var (
	ErrKeySize = errors.New("invalid key size")
	ErrIVSize  = errors.New("invalid iv size")
)

var schemes = make(internal.Schemes[Scheme])

func init() {
	Register(AESCTR128)
	Register(AESCTR256)
	Register(AESOFB128)
	Register(AESOFB256)
	Register(ChaCha20)
	Register(XChaCha20)
}

// Register registers a cipher scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the cipher scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered cipher algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered cipher schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
