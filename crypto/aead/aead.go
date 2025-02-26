// Package aead provides authenticated encryption with associated data
// but unlike the standard cipher.AEAD has a cipher.Stream-like interface
// and allows encrypting data streams.
package aead

import (
	"crypto/aes"

	"github.com/karalef/aead"
	"github.com/karalef/aead/chacha20poly1305"
	"github.com/karalef/aead/gcm"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/scheme"
)

// Cipher represents authenticated cipher.
type Cipher = aead.Stream

type (
	// Reader wraps a Cipher into an io.Reader.
	Reader = aead.Reader

	// Writer wraps a Cipher into an io.Writer.
	Writer = aead.Writer

	// BufferedWriter wraps a Cipher into an io.Writer. It allocates a buffer
	// on each Write call (like crypto/cipher.StreamWriter).
	BufferedWriter = aead.BufferedWriter
)

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
	// Panics if parameters have wrong sizes.
	Encrypt(key, nonce, associatedData []byte) Cipher

	// Decrypt returns Cipher in decryption mode.
	// Panics if parameters have wrong sizes.
	Decrypt(key, nonce, associatedData []byte) Cipher
}

// Verify compares the cipher tag and the provided one.
// Returns an error if MACs are not equal.
func Verify(c Cipher, tag []byte) error {
	if !mac.Equal(c.Tag(nil), tag) {
		return mac.ErrMismatch
	}
	return nil
}

// VerifySizes checks the key and nonce sizes.
func VerifySizes(s Scheme, key, nonce []byte) error {
	if s.KeySize() != len(key) {
		return ErrKeySize
	}
	if s.NonceSize() != len(nonce) {
		return ErrNonceSize
	}
	return nil
}

var (
	// AESGCM is the AES-GCM stream AEAD scheme.
	AESGCM = New("AESGCM", 32, gcm.NonceSize, gcm.TagSize,
		func(key, nonce, ad []byte) aead.Cipher {
			b, _ := aes.NewCipher(key)
			return gcm.NewCipher(b, nonce, ad, gcm.TagSize)
		})

	// ChaCha20Poly1305 is the ChaCha20-Poly1305 stream AEAD scheme.
	ChaCha20Poly1305 = New("ChaCha20_Poly1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSize, chacha20poly1305.TagSize,
		func(key, nonce, ad []byte) aead.Cipher {
			return chacha20poly1305.New(key, nonce, ad)
		})

	// XChaCha20Poly1305 is the XChaCha20-Poly1305 stream AEAD scheme.
	XChaCha20Poly1305 = New("XChaCha20_Poly1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSizeX, chacha20poly1305.TagSize,
		func(key, nonce, ad []byte) aead.Cipher {
			return chacha20poly1305.New(key, nonce, ad)
		})

	// ChaCha20BLAKE3 is the Encrypt-Then-MAC combination of ChaCha20 and BLAKE3.
	ChaCha20BLAKE3 = NewEtM("ChaCha20_BLAKE3", cipher.ChaCha20, mac.BLAKE3)

	// ChaCha20SHA3 is the Encrypt-Then-MAC combination of ChaCha20 and SHA3.
	ChaCha20SHA3 = NewEtM("ChaCha20_SHA3", cipher.ChaCha20, sha3k16)

	// AES256BLAKE3 is the Encrypt-Then-MAC combination of AES-CTR and BLAKE3.
	AES256BLAKE3 = NewEtM("AESCTR_BLAKE3", cipher.AESCTR, mac.BLAKE3)

	// AES256SHA3 is the Encrypt-Then-MAC combination of AES-CTR and SHA3.
	AES256SHA3 = NewEtM("AESCTR_SHA3", cipher.AESCTR, sha3k16)

	sha3k16 = mac.Fixed(mac.SHA3, 16)
)

func init() {
	Register(AESGCM)
	Register(ChaCha20Poly1305)
	Register(XChaCha20Poly1305)
	Register(ChaCha20BLAKE3)
	Register(ChaCha20SHA3)
	Register(AES256BLAKE3)
	Register(AES256SHA3)
}

var schemes = make(scheme.Map[Scheme])

// Register registers a AEAD scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the AEAD scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered AEAD algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered AEAD schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an AEAD algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
