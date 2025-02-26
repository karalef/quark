package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"

	"golang.org/x/crypto/chacha20"
)

func init() {
	Register(AESCTR)
	Register(ChaCha20)
	Register(XChaCha20)
}

// variants.
var (
	AESCTR    = New("AESCTR", 32, aes.BlockSize, aes.BlockSize, newAESCTR)
	ChaCha20  = New("ChaCha20", chacha20.KeySize, chacha20.NonceSize, 64, newChaCha20)
	XChaCha20 = New("XChaCha20", chacha20.KeySize, chacha20.NonceSizeX, 64, newChaCha20)
)

func newAESCTR(key, iv []byte) Cipher {
	block, _ := aes.NewCipher(key)
	return stdcipher.NewCTR(block, iv)
}

func newChaCha20(key, iv []byte) Cipher {
	c, _ := chacha20.NewUnauthenticatedCipher(key, iv)
	return c
}
