package pke

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/pke/internal"
)

// Encrypt is wrapper for PublicKey.Encrypt with random seed.
func Encrypt(p PublicKey, plaintext []byte) (ciphertext []byte, err error) {
	return p.Encrypt(plaintext, crypto.Rand(p.Scheme().EncryptionSeedSize()))
}

// Scheme represents a Public Key Encryption scheme.
type Scheme = internal.Scheme

// PrivateKey represents a PKE private key.
type PrivateKey = internal.PrivateKey

// PublicKey represents a PKE public key.
type PublicKey = internal.PublicKey

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = internal.ErrKeySize

// ErrSeedSize is an error with which DeriveKey panics.
var ErrSeedSize = internal.ErrSeedSize

// ErrPlaintext is returned when the plaintext size is invalid.
var ErrPlaintext = internal.ErrPlaintext

// ErrCiphertext is returned when the ciphertext size is invalid.
var ErrCiphertext = internal.ErrCiphertext

// ErrEncryptionSeed is an error with which Encrypt panics.
var ErrEncryptionSeed = internal.ErrEncryptionSeed
