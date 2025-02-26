package pke

import (
	"errors"

	"github.com/karalef/quark/crypto"
)

// Encrypt is wrapper for PublicKey.Encrypt with random seed.
func Encrypt(p PublicKey, plaintext []byte) (ciphertext []byte, err error) {
	return p.Encrypt(plaintext, crypto.Rand(p.Scheme().EncryptionSeedSize()))
}

// Scheme represents a Public Key Encryption scheme.
type Scheme interface {
	crypto.KeyScheme[PublicKey, PrivateKey]

	// Size of ciphertext.
	Size() int

	// Size of plaintext.
	PlaintextSize() int

	// Size of encryption seed.
	EncryptionSeedSize() int
}

// PrivateKey represents a PKE private key.
type PrivateKey interface {
	crypto.PrivateKey[Scheme, PrivateKey, PublicKey]

	// Decrypt decrypts ciphertext.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a PKE public key.
type PublicKey interface {
	crypto.PublicKey[Scheme, PublicKey]

	// Encrypt encryts a plaintext using provided seed.
	Encrypt(plaintext, seed []byte) ([]byte, error)
}

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

// ErrSeedSize is an error with which DeriveKey panics.
var ErrSeedSize = errors.New("invalid seed size")

// ErrPlaintext is returned when the plaintext size is invalid.
var ErrPlaintext = errors.New("invalid plaintext size")

// ErrCiphertext is returned when the ciphertext size is invalid.
var ErrCiphertext = errors.New("invalid ciphertext size")

// ErrEncryptionSeed is an error with which Encrypt panics.
var ErrEncryptionSeed = errors.New("invalid encryption seed size")
