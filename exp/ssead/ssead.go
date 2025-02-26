// package ssead introduces Signed Stream Encryption with Associated Data.
// Basically, it's a stream cipher with a signature.
package ssead

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/scheme"
)

// Encrypter represents cipher in encryption mode.
type Encrypter interface {
	Encrypt(dst, src []byte)
	Sign() []byte
}

// Decrypter represents cipher in decryption mode.
type Decrypter interface {
	Decrypt(dst, src []byte)

	// Verify verifies the signature.
	// Returns false if the signature is wrong and an error if the
	// signature is invalid.
	Verify(signature []byte) (bool, error)
}

// Scheme represents the Signed Stream Encryption with Associated Data scheme.
type Scheme interface {
	scheme.Scheme

	// KeySize returns the key size in bytes.
	KeySize() int

	// IVSize returns the iv size in bytes.
	IVSize() int

	// SignatureSize returns the signature size in bytes.
	SignatureSize() int

	// Encrypt returns cipher in encryption mode.
	// Panics if parameters have wrong sizes.
	Encrypt(sk sign.PrivateKey, key, iv, associatedData []byte) Encrypter

	// Decrypt returns cipher in decryption mode.
	// Panics if parameters have wrong sizes.
	Decrypt(pk sign.PublicKey, key, iv, associatedData []byte) Decrypter
}

// errors.
var (
	ErrKeySize = cipher.ErrKeySize
	ErrIVSize  = cipher.ErrIVSize
)

var schemes = make(scheme.Map[Scheme])

// Register registers a SSEAD scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the SSEAD scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered SSEAD algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered SSEAD schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an SSEAD algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
