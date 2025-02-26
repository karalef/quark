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

// Read reads exactly len(dst) bytes from src into dst. If src is nil,
// cryto/rand is used. Panics if error occured.
func Read(dst []byte, src io.Reader) {
	if _, err := io.ReadFull(Reader(src), dst); err != nil {
		panic(err)
	}
}

// RandRead allocates and reads a random byte slice of length size.
// If rand is nil, crypto/rand is used. Panics if error occured.
func RandRead(rand io.Reader, size int) []byte {
	buf := make([]byte, size)
	Read(buf, rand)
	return buf
}

// Rand allocates and reads a random byte slice of length size using crypto/rand.
// Panics if crypto/rand returns an error.
func Rand(size int) []byte {
	return RandRead(nil, size)
}

// RandUint64 reads a random uint64 using crypto/rand. Panics if error occured.
func RandUint64() uint64 {
	var b [8]byte
	Read(b[:], nil)
	return binary.BigEndian.Uint64(b[:])
}
