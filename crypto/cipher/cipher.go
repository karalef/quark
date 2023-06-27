package cipher

import (
	stdcipher "crypto/cipher"
	"errors"

	"github.com/karalef/quark/crypto/internal"
)

// Stream represents a stream cipher.
type Stream interface {
	Scheme() Scheme

	stdcipher.Stream
}

// Scheme type.
type Scheme interface {
	Name() string

	KeySize() int
	IVSize() int

	New(key, iv []byte) (Stream, error)
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	name    string
	newFunc func(s Scheme, key, iv []byte) (Stream, error)
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
	return s.newFunc(s, key, iv)
}

var _ Stream = baseStream{}

type baseStream struct {
	scheme Scheme
	stdcipher.Stream
}

func (s baseStream) Scheme() Scheme { return s.scheme }

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
