// package crypto contains cryptographic primitives (like hashes, ciphers,
// PKI, etc.) and some algorithms over them (like KDFs, PRFs, etc.).
package crypto

import (
	"crypto/subtle"
	"io"
)

// NewWriter returns a writer that returns no error.
func NewWriter(w io.Writer) Writer { return writer{w} }

// Writer is a writer that returns no error.
type Writer interface {
	Write([]byte)
	WriteString(string)
}

type writer struct{ io.Writer }

//nolint:errcheck
func (w writer) Write(p []byte) {
	n, err := w.Writer.Write(p)
	if err != nil {
		panic(err)
	}
	if n != len(p) {
		panic(io.ErrShortWrite)
	}
}

func (w writer) WriteString(s string) { w.Write([]byte(s)) }

// Equal compares two byte slices in constant time and returns true if they are
// equal.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// OrPanic returns v if err is nil, panics otherwise.
func OrPanic[V any](v V, err error) V {
	if err != nil {
		panic(err)
	}
	return v
}

// LenOrPanic compares the length of b to req and panics with err if they are
// not equal.
func LenOrPanic(b []byte, req int, err error) {
	if len(b) != req {
		panic(err)
	}
}
