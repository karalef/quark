package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	aesgcmNonceSize = 24
	aesgcmOverhead  = 12
)

var (
	aesgcm128Scheme = aesgcmScheme{
		baseScheme: baseScheme{
			Algorithm: AESGCM128,
			keySize:   16,
			nonceSize: aesgcmNonceSize,
			overhead:  aesgcmOverhead,
		},
	}
	aesgcm192Scheme = aesgcmScheme{
		baseScheme: baseScheme{
			Algorithm: AESGCM192,
			keySize:   24,
			nonceSize: aesgcmNonceSize,
			overhead:  aesgcmOverhead,
		},
	}
	aesgcm256Scheme = aesgcmScheme{
		baseScheme: baseScheme{
			Algorithm: AESGCM256,
			keySize:   32,
			nonceSize: aesgcmNonceSize,
			overhead:  aesgcmOverhead,
		},
	}
)

type aesgcmScheme struct {
	baseScheme
}

func (s aesgcmScheme) Unpack(key []byte) (Cipher, error) {
	if len(key) != s.keySize {
		return nil, errors.New("invalid key size")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(c, s.nonceSize)
	if err != nil {
		return nil, err
	}
	return &aesgcm{
		scheme: s,
		aead:   aead,
	}, nil
}

var _ Cipher = &aesgcm{}

type aesgcm struct {
	scheme aesgcmScheme
	aead   cipher.AEAD
}

func (a *aesgcm) Scheme() Scheme { return a.scheme }

func (a *aesgcm) Seal(dst, nonce, plaintext []byte) []byte {
	return a.aead.Seal(dst, nonce, plaintext, nil)
}

func (a *aesgcm) Open(dst, nonce, ciphertext []byte) ([]byte, error) {
	return a.aead.Open(dst, nonce, ciphertext, nil)
}
