package cipher

import (
	"golang.org/x/crypto/chacha20"
)

// ChaCha20 scheme.
var ChaCha20 Scheme = &baseScheme{
	name:    "CHACHA20",
	keySize: chacha20.KeySize,
	ivSize:  chacha20.NonceSize,
	newFunc: newChaCha20,
}

// XChaCha20 scheme.
var XChaCha20 Scheme = &baseScheme{
	name:    "XCHACHA20",
	keySize: chacha20.KeySize,
	ivSize:  chacha20.NonceSizeX,
	newFunc: newChaCha20,
}

func newChaCha20(s Scheme, key, iv []byte) (Stream, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		return nil, err
	}
	return baseStream{
		scheme: s,
		Stream: cipher,
	}, nil
}
