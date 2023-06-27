package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
)

// aes variants.
var (
	AESCTR128 = baseScheme{
		name:    "AESCTR128",
		keySize: 16,
		ivSize:  aes.BlockSize,
		newFunc: newAESCTR,
	}
	AESCTR256 = baseScheme{
		name:    "AESCTR256",
		keySize: 32,
		ivSize:  aes.BlockSize,
		newFunc: newAESCTR,
	}
	AESOFB128 = baseScheme{
		name:    "AESOFB128",
		keySize: 16,
		ivSize:  aes.BlockSize,
		newFunc: newAESOFB,
	}
	AESOFB256 = baseScheme{
		name:    "AESOFB256",
		keySize: 32,
		ivSize:  aes.BlockSize,
		newFunc: newAESOFB,
	}
)

func newAESCTR(s Scheme, key, iv []byte) (Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return baseStream{
		scheme: s,
		Stream: stdcipher.NewCTR(block, iv),
	}, nil
}

func newAESOFB(s Scheme, key, iv []byte) (Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return baseStream{
		scheme: s,
		Stream: stdcipher.NewOFB(block, iv),
	}, nil
}
