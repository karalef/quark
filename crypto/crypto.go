package crypto

import "crypto/subtle"

// Copy copies b to a new slice.
func Copy(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

// Compare compares two byte slices in constant time.
func Compare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// OrPanic returns v if err is nil, otherwise it panics.
func OrPanic[V any](v V, err error) V {
	if err != nil {
		panic(err)
	}
	return v
}
