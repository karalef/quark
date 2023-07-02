package ae

import "io"

// Reader wraps an AE into an io.Reader.
type Reader struct {
	AE AE
	R  io.Reader
}

func (r Reader) Read(dst []byte) (n int, err error) {
	n, err = r.R.Read(dst)
	r.AE.Crypt(dst[:n], dst[:n])
	return
}

// BufferedWriter wraps an AE into an io.Writer.
// It allocates a buffer on each Write call (like crypto/cipher.StreamWriter).
type BufferedWriter struct {
	AE AE
	W  io.Writer
}

func (w BufferedWriter) Write(src []byte) (n int, err error) {
	buf := make([]byte, len(src))
	w.AE.Crypt(buf, src)
	n, err = w.W.Write(buf)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}

// Writer wraps an AE into an io.Writer.
// It has no internal buffering before encryption so the provided src will be modified.
type Writer struct {
	AE AE
	W  io.Writer
}

func (w Writer) Write(src []byte) (n int, err error) {
	w.AE.Crypt(src, src)
	n, err = w.W.Write(src)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}
