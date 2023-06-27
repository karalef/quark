package kdf

import (
	"errors"

	"github.com/karalef/quark/crypto/internal"
)

// KDF represents the key derivation function.
type KDF interface {
	Name() string

	// Derive derives a key of the specified size from a password and salt.
	// Panics if size is zero.
	Derive(password, salt []byte, size int, params Params) ([]byte, error)
}

// Params represents the key derivation function parameters.
// Params must be encodable/decodable for msgpack.
type Params interface {
	Validate() error
}

// ErrPassword is returned when the password is empty.
var ErrPassword = errors.New("kdf: empty password")

// ErrInvalidParams is returned when the parameters are invalid.
type ErrInvalidParams struct {
	Err error
}

func (e ErrInvalidParams) Error() string {
	return "kdf: invalid parameters: " + e.Err.Error()
}

type baseKDF[T Params] struct {
	kdf  func(password, salt []byte, size int, params T) ([]byte, error)
	name string
}

func (kdf baseKDF[T]) Name() string {
	return kdf.name
}

func (kdf baseKDF[T]) Derive(password, salt []byte, size int, params Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrPassword
	}
	p, ok := params.(T)
	if !ok {
		return nil, ErrInvalidParams{
			Err: errors.New("type of Params does not match the KDF"),
		}
	}
	err := p.Validate()
	if err != nil {
		return nil, ErrInvalidParams{
			Err: err,
		}
	}
	return kdf.kdf(password, salt, size, p)
}

var kdfs = make(internal.Schemes[KDF])

func init() {
	Register(Argon2i)
	Register(Argon2id)
	Register(Scrypt)
}

// Register registers a KDF.
func Register(kdf KDF) { kdfs.Register(kdf) }

// ByName returns the KDF by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) KDF { return kdfs.ByName(name) }
