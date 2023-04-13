package internal

import "io"

// WriteFull writes b to w in one operation.
// If a write accepted fewer bytes than requested io.ErrShortWrite is returned.
func WriteFull(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
