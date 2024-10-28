// Package aead provides authenticated encryption with associated data
// but unlike the standard cipher.AEAD has a cipher.Stream-like interface
// and allows encrypting data streams.
package aead

import (
	"github.com/karalef/quark/crypto/aead/chacha20poly1305"
	"github.com/karalef/quark/crypto/aead/etm"
	"github.com/karalef/quark/crypto/aead/internal"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/scheme"
)

// Cipher represents authenticated cipher.
type Cipher = internal.Cipher

// Scheme represents an AEAD scheme.
type Scheme interface {
	scheme.Scheme

	// KeySize returns the key size in bytes.
	KeySize() int

	// NonceSize returns the nonce size in bytes.
	NonceSize() int

	// TagSize returns the tag size in bytes.
	TagSize() int

	// Encrypt returns Cipher in encryption mode.
	// Panics if nonce is not of length NonceSize().
	Encrypt(key, nonce, associatedData []byte) (Cipher, error)

	// Decrypt returns Cipher in decryption mode.
	// Panics if nonce is not of length NonceSize().
	Decrypt(key, nonce, associatedData []byte) (Cipher, error)
}

// NewFunc represents the function to create an AEAD cipher.
type NewFunc = internal.NewFunc

// New creates new AEAD scheme.
// It does not register the scheme.
// The returned scheme guarantees the correct key and nonce lengths
// that are passed to the enc and dec functions.
func New(name string, keySize, nonceSize, tagSize int, enc, dec NewFunc) Scheme {
	return internal.New(name, keySize, nonceSize, tagSize, enc, dec)
}

// errors.
var (
	ErrKeySize   = internal.ErrKeySize
	ErrNonceSize = internal.ErrNonceSize
)

var (
	// ChaCha20Poly1305 is the ChaCha20-Poly1305 stream AEAD scheme.
	ChaCha20Poly1305 = New("CHACHA20POLY1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSize, chacha20poly1305.TagSize,
		chacha20poly1305.NewEncrypter, chacha20poly1305.NewDecrypter)

	// XChaCha20Poly1305 is the XChaCha20-Poly1305 stream AEAD scheme.
	XChaCha20Poly1305 = New("XCHACHA20POLY1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSizeX, chacha20poly1305.TagSize,
		chacha20poly1305.NewEncrypter, chacha20poly1305.NewDecrypter)

	// ChaCha20Blake3 is the Encrypt-Then-MAC combination of ChaCha20 and BLAKE3.
	ChaCha20Blake3 = etm.Build("CHACHA20BLAKE3", cipher.ChaCha20, mac.BLAKE3)

	// AES256Blake3 is the Encrypt-Then-MAC combination of AES256-CTR and BLAKE3.
	AES256Blake3 = etm.Build("AES256BLAKE3", cipher.AESCTR256, mac.BLAKE3)

	// AES256SHA3 is the Encrypt-Then-MAC combination of AES256-CTR and SHA3.
	AES256SHA3 = etm.Build("AES256SHA3", cipher.AESCTR256, mac.Fixed(mac.SHA3, 16))
)

func init() {
	Register(ChaCha20Poly1305)
	Register(ChaCha20Blake3)
	Register(AES256Blake3)
	Register(AES256SHA3)
}

var schemes = make(scheme.Schemes[Scheme])

// Register registers a AEAD scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the AEAD scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListAll returns all registered AEAD algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered AEAD schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
