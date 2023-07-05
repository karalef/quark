package compress

import (
	"compress/flate"
	"errors"
	"io"

	"github.com/karalef/quark/internal"
	"github.com/pierrec/lz4/v4"
	"github.com/valyala/gozstd"
)

// Compression represents compression algorithm.
type Compression interface {
	Name() string

	// MaxLevel returns the maximum compression level.
	MaxLevel() uint

	// DefaultLevel returns the default compression level (0 passed to Compress).
	DefaultLevel() uint

	Compress(w io.Writer, level uint, opts Opts) (io.WriteCloser, error)
	Decompress(r io.Reader, opts Opts) (io.Reader, error)
}

// Opts represents compression options.
type Opts interface {
	CompressOpts()
}

// ErrInvalidLevel is returned when the compression level is bigger than MaxLevel().
var ErrInvalidLevel = errors.New("compress: invalid compression level")

// ErrWrongOpts is returned when wrong options type is used.
var ErrWrongOpts = errors.New("compress: wrong options type")

// Deflate compression.
var Deflate = compression[Opts]{
	name:     "deflate",
	maxLevel: uint(flate.BestCompression),
	defLevel: 6,
	compress: func(w io.Writer, lvl uint, _ Opts) (io.WriteCloser, error) {
		return flate.NewWriter(w, int(lvl))
	},
	decompress: func(r io.Reader, _ Opts) (io.Reader, error) {
		return flate.NewReader(r), nil
	},
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

// LZ4 compression.
var LZ4 = compression[LZ4Opts]{
	name:     "lz4",
	maxLevel: 9,
	defLevel: 0,
	compress: func(w io.Writer, lvl uint, opts LZ4Opts) (io.WriteCloser, error) {
		lz4lvl := lz4.Fast
		if lvl > 0 {
			lz4lvl = lz4.CompressionLevel(1 << (8 + lvl))
		}
		lz4w := lz4.NewWriter(w)
		return lz4w, lz4w.Apply(
			lz4.CompressionLevelOption(lz4lvl),
			lz4.ConcurrencyOption(int(opts.Threads)),
		)
	},
	decompress: func(r io.Reader, opts LZ4Opts) (io.Reader, error) {
		lz4r := lz4.NewReader(r)
		return lz4r, lz4r.Apply(lz4.ConcurrencyOption(int(opts.Threads)))
	},
}

// LZ4Opts contains optional parameters for lz4.
type LZ4Opts struct {
	// if == 0, runtime.GOMAXPROCS(0) is used
	Threads uint
}

// CompressOpts func.
func (LZ4Opts) CompressOpts() {}

var _ Compression = compression[Opts]{}

type compression[T Opts] struct {
	compress   func(io.Writer, uint, T) (io.WriteCloser, error)
	decompress func(io.Reader, T) (io.Reader, error)
	name       string
	maxLevel   uint
	defLevel   uint
}

func (c compression[T]) Name() string       { return c.name }
func (c compression[T]) MaxLevel() uint     { return c.maxLevel }
func (c compression[T]) DefaultLevel() uint { return c.defLevel }

func (c compression[T]) Compress(w io.Writer, lvl uint, opts Opts) (io.WriteCloser, error) {
	if lvl > c.maxLevel {
		return nil, ErrInvalidLevel
	}
	if lvl == 0 {
		lvl = c.defLevel
	}
	o, ok := opts.(T)
	if opts != nil && !ok {
		return nil, ErrWrongOpts
	}
	return c.compress(w, lvl, o)
}

func (c compression[T]) Decompress(r io.Reader, opts Opts) (io.Reader, error) {
	o, ok := opts.(T)
	if opts != nil && !ok {
		return nil, ErrWrongOpts
	}
	return c.decompress(r, o)
}

var compressions = make(internal.Schemes[Compression])

func init() {
	Register(Deflate)
	Register(ZSTD)
	Register(LZ4)
}

// Register registers a compression algorithm.
func Register(c Compression) { compressions.Register(c) }

// ByName returns the compression algorithm by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Compression { return compressions.ByName(name) }

// ListAll returns all registered compression algorithms.
func ListAll() []string { return compressions.ListAll() }

// ListSchemes returns all registered compressions.
func ListSchemes() []Compression { return compressions.ListSchemes() }
