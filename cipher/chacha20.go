package cipher

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Poly1305 returns XChaCha20-Poly1305 scheme.
func XChaCha20Poly1305() Scheme { return xchacha20poly1305Scheme }

var xchacha20poly1305Scheme Scheme = baseScheme{
	keySize:   chacha20poly1305.KeySize,
	nonceSize: chacha20poly1305.NonceSizeX,
	overhead:  chacha20poly1305.Overhead,
	unpack:    newXChaCha20Poly1305,
}

var _ Cipher = &xchacha20poly1305{}

type xchacha20poly1305 struct {
	aead cipher.AEAD
}

func (*xchacha20poly1305) Scheme() Scheme { return xchacha20poly1305Scheme }

func (x *xchacha20poly1305) Seal(dst, nonce, plaintext []byte) []byte {
	return x.aead.Seal(dst, nonce, plaintext, nil)
}

func (x *xchacha20poly1305) Open(dst, nonce, ciphertext []byte) ([]byte, error) {
	return x.aead.Open(dst, nonce, ciphertext, nil)
}

func newXChaCha20Poly1305(key []byte) (Cipher, error) {
	ciph, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &xchacha20poly1305{aead: ciph}, nil
}
