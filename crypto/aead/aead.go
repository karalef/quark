// Package aead provides authenticated encryption with associated data
// but unlike the standard cipher.AEAD has a cipher.Stream-like interface
// and allows encrypting data streams.
package aead

import (
	"crypto/aes"

	"github.com/karalef/quark/crypto/aead/chacha20poly1305"
	"github.com/karalef/quark/crypto/aead/gcm"
	"github.com/karalef/quark/crypto/aead/internal"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/hmac"
	"github.com/karalef/quark/scheme"
)

// Cipher represents authenticated cipher.
type Cipher interface {
	// Crypt XORs each byte in the given slice with a byte from the cipher's key
	// stream and authenticates the data depending on the algorithm.
	//
	// Dst and src must overlap entirely or not at all. If len(dst) < len(src),
	// Crypt will panic. It is acceptable to pass a dst bigger than src, and in
	// that case, Crypt will only update dst[:len(src)] and will not touch the
	// rest of dst.
	//
	// Multiple calls to Crypt behave as if the concatenation of the src buffers
	// was passed in a single run. That is, Stream maintains state and does not
	// reset at each Crypt call.
	Crypt(dst, src []byte)

	// TagSize returns the tag size in bytes.
	TagSize() int

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}

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
	if !hmac.Equal(c.Tag(nil), tag) {
		return hmac.ErrMismatch
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
		func(key, nonce, ad []byte) internal.Cipher {
			b, _ := aes.NewCipher(key)
			return gcm.NewCipher(b, nonce, ad, gcm.TagSize)
		})

	// ChaCha20Poly1305 is the ChaCha20-Poly1305 stream AEAD scheme.
	ChaCha20Poly1305 = New("ChaCha20_Poly1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSize, chacha20poly1305.TagSize,
		func(key, nonce, ad []byte) internal.Cipher {
			return chacha20poly1305.New(key, nonce, ad)
		})

	// XChaCha20Poly1305 is the XChaCha20-Poly1305 stream AEAD scheme.
	XChaCha20Poly1305 = New("XChaCha20_Poly1305", chacha20poly1305.KeySize,
		chacha20poly1305.NonceSizeX, chacha20poly1305.TagSize,
		func(key, nonce, ad []byte) internal.Cipher {
			return chacha20poly1305.New(key, nonce, ad)
		})

	// ChaCha20BLAKE3 is the Encrypt-Then-MAC combination of ChaCha20 and BLAKE3.
	ChaCha20BLAKE3 = NewEtM("ChaCha20_BLAKE3", cipher.ChaCha20, hmac.BLAKE3)

	// AES256SHA3 is the Encrypt-Then-MAC combination of AES-CTR and SHA3.
	AES256SHA3 = NewEtM("AESCTR_SHA3", cipher.AESCTR, hmac.SHA3)
)

func init() {
	Schemes.Register(AESGCM)
	Schemes.Register(ChaCha20Poly1305)
	Schemes.Register(XChaCha20Poly1305)
	Schemes.Register(ChaCha20BLAKE3)
	Schemes.Register(AES256SHA3)
}

// Schemes is a registry of AEAD schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }

// Algorithm is an AEAD algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
