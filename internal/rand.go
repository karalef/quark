package internal

import (
	cryptorand "crypto/rand"
	"io"
)

// RandRead allocates a random byte slice of length size.
// If rand is nil, crypto/rand is used.
func RandRead(rand io.Reader, size int) ([]byte, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Rand allocates a random byte slice of length size.
// Panics if crypto/rand returns an error.
func Rand(size int) []byte {
	buf, err := RandRead(nil, size)
	if err != nil {
		panic(err)
	}
	return buf
}
