package cipher

import (
	"golang.org/x/crypto/chacha20"
)

func init() {
	Register(ChaCha20)
	Register(XChaCha20)
}

// ChaCha20 scheme.
var ChaCha20 = New("CHACHA20", chacha20.KeySize, chacha20.NonceSize, newChaCha20)

// XChaCha20 scheme.
var XChaCha20 = New("XCHACHA20", chacha20.KeySize, chacha20.NonceSizeX, newChaCha20)

func newChaCha20(key, iv []byte) (Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(key, iv)
}
