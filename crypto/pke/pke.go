package pke

import (
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/scheme"
)

// Generate derives a key-pair from a seed generated by provided rand.
//
// If rand is nil, crypto/rand is used.
func Generate(s Scheme, rand io.Reader) (PrivateKey, PublicKey, error) {
	seed, err := crypto.RandRead(rand, s.SeedSize())
	if err != nil {
		return nil, nil, err
	}
	return s.DeriveKey(seed)
}

// Encrypt is wrapper for PublicKey.Encrypt with random seed.
func Encrypt(p PublicKey, plaintext []byte) (ciphertext []byte, err error) {
	return p.Encrypt(plaintext, crypto.Rand(p.Scheme().(Scheme).EncryptionSeedSize()))
}

// Scheme represents a Public Key Encryption scheme.
type Scheme interface {
	crypto.Scheme

	// DeriveKey derives a key-pair from a seed.
	DeriveKey(seed []byte) (PrivateKey, PublicKey, error)

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (PublicKey, error)

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (PrivateKey, error)

	// Size of ciphertext.
	CiphertextSize() int

	// Size of plaintext.
	PlaintextSize() int

	// Size of encryption seed.
	EncryptionSeedSize() int
}

// PrivateKey represents a PKE private key.
type PrivateKey interface {
	// The scheme returned by Scheme() must implement the Scheme interface.
	crypto.Key
	Public() PublicKey
	Equal(PrivateKey) bool

	// Decrypt decrypts ciphertext.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a PKE public key.
type PublicKey interface {
	// The scheme returned by Scheme() must implement the Scheme interface.
	crypto.Key
	CorrespondsTo(PrivateKey) bool
	Equal(PublicKey) bool

	// Encrypt encryts a plaintext using provided seed.
	Encrypt(plaintext, seed []byte) ([]byte, error)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (PublicKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (PrivateKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

// errors.
var (
	ErrKeySize        = errors.New("invalid key size")
	ErrSeedSize       = errors.New("invalid seed size")
	ErrPlaintext      = errors.New("invalid plaintext size")
	ErrCiphertext     = errors.New("invalid ciphertext size")
	ErrEncryptionSeed = errors.New("invalid encryption seed size")
)

var schemes = make(scheme.Schemes[Scheme])

// Register registers a PKE scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the PKE scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListAll returns all registered PKE algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered PKE schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
