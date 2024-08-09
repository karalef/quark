//go:build !windows
// +build !windows

package compress

import (
	"io"

	"github.com/valyala/gozstd"
)

func init() {
	Register(ZSTD)
}

// ZSTD compression.
var ZSTD = compression[Opts]{
	name:     "zstd",
	maxLevel: 22,
	defLevel: uint(gozstd.DefaultCompressionLevel),
	compress: func(w io.Writer, lvl uint, _ Opts) (io.WriteCloser, error) {
		return zstdWriter{gozstd.NewWriterLevel(w, int(lvl))}, nil
	},
	decompress: func(r io.Reader, _ Opts) (io.Reader, error) {
		return gozstd.NewReader(r), nil
	},
}

type zstdWriter struct {
	*gozstd.Writer
}

func (w zstdWriter) Close() error {
	defer w.Writer.Release()
	return w.Writer.Close()
}
