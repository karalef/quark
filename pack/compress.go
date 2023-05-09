package pack

import (
	"compress/flate"
	"errors"
	"io"

	"github.com/pierrec/lz4/v4"
	"github.com/valyala/gozstd"
)

// Compression represents compression algorithm.
type Compression byte

// compression algorithms.
const (
	NoCompression Compression = iota
	Deflate
	Zstd
	Lz4
)

// CompressionOpts contains optional parameters for de/compression.
type CompressionOpts struct {
	// used in lz4
	// if == 0, runtime.GOMAXPROCS(0) is used
	Threads uint
}

var defaultCompressionOpts = &CompressionOpts{
	Threads: 0,
}

func compressDeflate(w io.Writer, lvl int, opts CompressionOpts) (io.WriteCloser, error) {
	if lvl == 0 {
		lvl = flate.DefaultCompression
	}
	return flate.NewWriter(w, int(lvl))
}

type zstdCompressor struct {
	*gozstd.Writer
}

func (c zstdCompressor) Close() error {
	defer c.Writer.Release()
	return c.Writer.Close()
}

func compressZstd(w io.Writer, lvl int, opts CompressionOpts) (io.WriteCloser, error) {
	return zstdCompressor{gozstd.NewWriterLevel(w, lvl)}, nil
}

func compressLz4(w io.Writer, lvl int, opts CompressionOpts) (io.WriteCloser, error) {
	lz4lvl := lz4.Fast
	if lvl > 0 {
		lz4lvl = lz4.CompressionLevel(1 << (8 + lvl))
	}
	lz4w := lz4.NewWriter(w)
	return lz4w, lz4w.Apply(
		lz4.CompressionLevelOption(lz4lvl),
		lz4.ConcurrencyOption(int(opts.Threads)),
	)
}

// Compress compresses a writer.
// If lvl is 0, the default compression level is used.
// If lvl <0, -lvl is used.
func Compress(w io.Writer, alg Compression, lvl int, opts *CompressionOpts) (io.WriteCloser, error) {
	if lvl < 0 {
		lvl = -lvl
	}
	if opts == nil {
		opts = defaultCompressionOpts
	}
	switch alg {
	case NoCompression:
		return NopCloser(w), nil
	case Deflate:
		return compressDeflate(w, lvl, *opts)
	case Zstd:
		return compressZstd(w, lvl, *opts)
	case Lz4:
		return compressLz4(w, lvl, *opts)
	}
	return nil, errors.New("unknown compression algorithm")
}

// deflateDecompressor is a wrapper around flate.Reader that calls Close after EOF.
type deflateDecompressor struct {
	f io.ReadCloser
}

func (d deflateDecompressor) Read(p []byte) (n int, err error) {
	n, err = d.f.Read(p)
	if err == io.EOF {
		err1 := d.f.Close()
		if err1 != nil {
			err = err1
		}
	}
	return
}

// Decompress decompresses a reader.
func Decompress(r io.Reader, alg Compression, opts *CompressionOpts) (io.Reader, error) {
	if opts == nil {
		opts = defaultCompressionOpts
	}
	switch alg {
	default:
		return nil, errors.New("unknown compression algorithm")
	case NoCompression:
	case Deflate:
		r = deflateDecompressor{flate.NewReader(r)}
	case Zstd:
		r = gozstd.NewReader(r)
	case Lz4:
		lz4r := lz4.NewReader(r)
		lz4r.Apply(lz4.ConcurrencyOption(int(opts.Threads)))
		r = lz4r
	}
	return r, nil
}
