package crypto

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
)

// Reader returns r if it is not nil, otherwise crypto/rand.Reader.
func Reader(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return cryptorand.Reader
}

// RandRead allocates and reads a random byte slice of length size.
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

// Rand allocates and reads a random byte slice of length size using crypto/rand.
// Panics if crypto/rand returns an error.
func Rand(size int) []byte {
	return OrPanic(RandRead(nil, size))
}

// RandUint64 reads a random uint64 using crypto/rand.
func RandUint64() uint64 {
	var b [8]byte
	OrPanic(cryptorand.Read(b[:]))
	return binary.BigEndian.Uint64(b[:])
}
