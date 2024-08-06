package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
)

func init() {
	Register(AESCTR256)
	Register(AESOFB256)
}

// aes variants.
var (
	AESCTR256 = New("AES_CTR256", 32, aes.BlockSize, newAESCTR)
	AESOFB256 = New("AES_OFB256", 32, aes.BlockSize, newAESOFB)
)

func newAESCTR(key, iv []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewCTR(block, iv), nil
}

func newAESOFB(key, iv []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewOFB(block, iv), nil
}
