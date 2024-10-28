package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"

	"golang.org/x/crypto/chacha20"
)

func init() {
	Register(AESCTR256)
	Register(AESOFB256)
	Register(ChaCha20)
	Register(XChaCha20)
}

// aes variants.
var (
	AESCTR256 = New("AES_CTR256", 32, aes.BlockSize, aes.BlockSize, newAESCTR)
	AESOFB256 = New("AES_OFB256", 32, aes.BlockSize, aes.BlockSize, newAESOFB)
)

// chacha20 variants.
var (
	ChaCha20  = New("CHACHA20", chacha20.KeySize, chacha20.NonceSize, 64, newChaCha20)
	XChaCha20 = New("XCHACHA20", chacha20.KeySize, chacha20.NonceSizeX, 64, newChaCha20)
)

func newAESCTR(key, iv []byte) Cipher {
	block, _ := aes.NewCipher(key)
	return stdcipher.NewCTR(block, iv)
}

func newAESOFB(key, iv []byte) Cipher {
	block, _ := aes.NewCipher(key)
	return stdcipher.NewOFB(block, iv)
}

func newChaCha20(key, iv []byte) Cipher {
	c, _ := chacha20.NewUnauthenticatedCipher(key, iv)
	return c
}
