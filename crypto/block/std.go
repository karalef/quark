package block

import (
	"crypto/aes"
)

func init() {
	Register(AES128)
	Register(AES192)
	Register(AES256)
}

// variants.
var (
	AES128 = New("AES128", 16, aes.BlockSize, newAES)
	AES192 = New("AES192", 24, aes.BlockSize, newAES)
	AES256 = New("AES256", 32, aes.BlockSize, newAES)
)

func newAES(key []byte) Cipher {
	block, _ := aes.NewCipher(key)
	return block
}
