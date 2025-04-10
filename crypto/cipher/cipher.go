package cipher

import (
	stdcipher "crypto/cipher"
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

// Cipher represents a stream cipher.
type Cipher = stdcipher.Stream

// Reader represents a stream cipher reader.
type Reader = stdcipher.StreamReader

// Writer represents a stream cipher writer.
type Writer = stdcipher.StreamWriter

// Scheme type.
type Scheme interface {
	scheme.Scheme

	KeySize() int
	IVSize() int

	// BlockSize returns the block size if the cipher has a counter.
	BlockSize() int

	// New creates a new cipher.
	// Panics if the key or iv length is wrong.
	New(key, iv []byte) Cipher
}

// NewFunc represents the function to create a stream cipher.
type NewFunc func(key, iv []byte) Cipher

// New creates new cipher scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key and iv lengths
// that are passed to the new.
func New(name string, keySize, ivSize, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		String:    scheme.String(name),
		keySize:   keySize,
		ivSize:    ivSize,
		blockSize: blockSize,
		newFunc:   new,
	}
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	scheme.String
	newFunc   NewFunc
	keySize   int
	ivSize    int
	blockSize int
}

func (s baseScheme) KeySize() int   { return s.keySize }
func (s baseScheme) IVSize() int    { return s.ivSize }
func (s baseScheme) BlockSize() int { return s.blockSize }

func (s baseScheme) New(key, iv []byte) Cipher {
	crypto.LenOrPanic(key, s.keySize, ErrKeySize)
	crypto.LenOrPanic(iv, s.ivSize, ErrIVSize)

	return s.newFunc(key, iv)
}

// VerifySizes verifies the key and iv sizes.
func VerifySizes(s Scheme, key, iv []byte) error {
	if len(key) != s.KeySize() {
		return ErrKeySize
	}
	if len(iv) != s.IVSize() {
		return ErrIVSize
	}
	return nil
}

// errors
var (
	ErrKeySize = errors.New("invalid key size")
	ErrIVSize  = errors.New("invalid iv size")
)

// Schemes is a registry of stream cipher schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }
