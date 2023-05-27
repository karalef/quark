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
	CompressionDeflate
	CompressionZstd
	CompressionLz4
)

// Compressor represents a compressor.
type Compressor interface {
	Algorithm() Compression
	Compress(w io.Writer) (io.WriteCloser, error)
}

// Decompressor represents a decompressor func.
type Decompressor func(r io.Reader, opts DecompressOpts) (io.Reader, error)

// DecompressOpts represents decompress options.
type DecompressOpts interface {
	DecompressOpts()
}

var _ Compressor = nopCompressor{}

type nopCompressor struct{}

func (nopCompressor) Algorithm() Compression                       { return NoCompression }
func (nopCompressor) Compress(w io.Writer) (io.WriteCloser, error) { return NopCloser(w), nil }

// Deflate returns a deflate compressor.
func Deflate(lvl int) Compressor {
	return deflateCompressor{lvl: lvl}
}

type deflateCompressor struct {
	lvl int
}

func (deflateCompressor) Algorithm() Compression { return CompressionDeflate }

func (c deflateCompressor) Compress(w io.Writer) (io.WriteCloser, error) {
	if c.lvl == 0 {
		c.lvl = flate.DefaultCompression
	}
	return flate.NewWriter(w, c.lvl)
}

type deflateDecompressor struct {
	fr io.ReadCloser
}

func (d deflateDecompressor) Read(p []byte) (n int, err error) {
	n, err = d.fr.Read(p)
	if err == io.EOF {
		err1 := d.fr.Close()
		if err1 != nil {
			err = err1
		}
	}
	return
}

func decompressDeflate(r io.Reader, _ DecompressOpts) (io.Reader, error) {
	return deflateDecompressor{fr: flate.NewReader(r)}, nil
}

// Zstd returns a zstd compressor.
func Zstd(lvl int) Compressor {
	return zstdCompressor{}
}

type zstdCompressor struct {
	lvl int
}

type zstdWriter struct {
	*gozstd.Writer
}

func (w zstdWriter) Close() error {
	defer w.Writer.Release()
	return w.Writer.Close()
}

func (zstdCompressor) Algorithm() Compression { return CompressionZstd }

func (c zstdCompressor) Compress(w io.Writer) (io.WriteCloser, error) {
	return zstdWriter{gozstd.NewWriterLevel(w, c.lvl)}, nil
}

func decompressZstd(r io.Reader, _ DecompressOpts) (io.Reader, error) {
	return gozstd.NewReader(r), nil
}

// Lz4 returns an lz4 compressor.
func Lz4(lvl int, opts ...Lz4Opts) Compressor {
	c := lz4Compressor{lvl: lvl}
	if len(opts) > 0 {
		c.opts = opts[0]
	}
	return c
}

// Lz4Opts contains optional parameters for lz4.
type Lz4Opts struct {
	// if == 0, runtime.GOMAXPROCS(0) is used
	Threads uint
}

// DecompressOpts func.
func (Lz4Opts) DecompressOpts() {}

type lz4Compressor struct {
	lvl  int
	opts Lz4Opts
}

func (lz4Compressor) Algorithm() Compression { return CompressionLz4 }

func (c lz4Compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	lz4lvl := lz4.Fast
	if c.lvl > 0 {
		lz4lvl = lz4.CompressionLevel(1 << (8 + c.lvl))
	}
	lz4w := lz4.NewWriter(w)
	return lz4w, lz4w.Apply(
		lz4.CompressionLevelOption(lz4lvl),
		lz4.ConcurrencyOption(int(c.opts.Threads)),
	)
}

func decompressLz4(r io.Reader, opts DecompressOpts) (io.Reader, error) {
	lz4r := lz4.NewReader(r)
	if opts, ok := opts.(Lz4Opts); ok {
		err := lz4r.Apply(lz4.ConcurrencyOption(int(opts.Threads)))
		if err != nil {
			return nil, err
		}
	}
	return lz4r, nil
}

// ErrUnsupportedCompression is returned when unsupported compression algorithm is used.
var ErrUnsupportedCompression = errors.New("unsupported compression algorithm")

// Compress compresses a writer.
func Compress(w io.Writer, c Compressor) (io.WriteCloser, error) {
	if c == nil {
		panic("nil Compressor")
	}
	if _, ok := compressors[c.Algorithm()]; !ok {
		return nil, ErrUnsupportedCompression
	}

	return c.Compress(w)
}

// Decompress decompresses a reader.
func Decompress(r io.Reader, alg Compression, opts DecompressOpts) (io.Reader, error) {
	decompress, ok := compressors[alg]
	if !ok {
		return nil, ErrUnsupportedCompression
	}
	return decompress(r, opts)
}

var compressors = map[Compression]Decompressor{
	NoCompression:      func(r io.Reader, _ DecompressOpts) (io.Reader, error) { return r, nil },
	CompressionDeflate: decompressDeflate,
	CompressionZstd:    decompressZstd,
	CompressionLz4:     decompressLz4,
}

// RegisterCompression registers a compression algorithm.
func RegisterCompression(alg Compression, decompress Decompressor) {
	if _, ok := compressors[alg]; ok {
		panic("duplicate compression algorithm")
	}
	if decompress == nil {
		panic("decompressor cannot be nil")
	}
	compressors[alg] = decompress
}
