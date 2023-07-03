package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
)

// aes variants.
var (
	AESCTR128 = New("AES_CTR128", 16, aes.BlockSize, newAESCTR)
	AESCTR256 = New("AES_CTR256", 32, aes.BlockSize, newAESCTR)
	AESOFB128 = New("AES_OFB128", 16, aes.BlockSize, newAESOFB)
	AESOFB256 = New("AES_OFB256", 32, aes.BlockSize, newAESOFB)
)

func newAESCTR(key, iv []byte) (Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewCTR(block, iv), nil
}

func newAESOFB(key, iv []byte) (Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewOFB(block, iv), nil
}
