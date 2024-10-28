package message

import (
	"errors"
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

// ChainCloser chains the wc to c.
func ChainCloser(c io.Closer, wc io.WriteCloser) io.WriteCloser {
	return chainedCloser{c, wc}
}

type chainedCloser struct {
	c io.Closer
	io.WriteCloser
}

func (c chainedCloser) Close() error {
	err := c.WriteCloser.Close()
	if err != nil {
		return errors.Join(err, c.c.Close())
	}
	return c.c.Close()
}
