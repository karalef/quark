package pack

import (
	"io"
)

// NopCloser is analog of io.NopCloser but for io.Writer.
func NopCloser(w io.Writer) io.WriteCloser {
	if _, ok := w.(io.ReaderFrom); ok {
		return nopCloserReaderFrom{w}
	}
	return nopCloser{w}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

var _ io.ReaderFrom = nopCloserReaderFrom{}

type nopCloserReaderFrom struct{ io.Writer }

func (nc nopCloserReaderFrom) ReadFrom(r io.Reader) (n int64, err error) {
	return nc.Writer.(io.ReaderFrom).ReadFrom(r)
}

func (nopCloserReaderFrom) Close() error { return nil }
