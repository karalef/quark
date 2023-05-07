package pack

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
)

// Compression represents compression algorithm.
type Compression byte

// compression algorithms.
const (
	NoCompression Compression = iota
	Flate
	Gzip
	Zlib
)

// compression levels.
const (
	LvlZero         = flate.NoCompression
	LvlHuffmanOnly  = flate.HuffmanOnly
	LvlDefault      = flate.DefaultCompression
	BestSpeed       = flate.BestSpeed
	BestCompression = flate.BestCompression
)

// Compress compresses a writer.
// The compression level can be LvlDefault, LvlZero, LvlHuffmanOnly or
// any integer value between BestSpeed and BestCompression inclusive.
func Compress(w io.Writer, alg Compression, lvl int) (io.WriteCloser, error) {
	switch alg {
	case NoCompression:
		return NopCloser(w), nil
	case Flate:
		return flate.NewWriter(w, lvl)
	case Gzip:
		return gzip.NewWriterLevel(w, lvl)
	case Zlib:
		return zlib.NewWriterLevel(w, lvl)
	}
	return nil, errors.New("unknown compression algorithm")
}

// Decompress decompresses a reader.
func Decompress(r io.Reader, alg Compression) (io.Reader, error) {
	var rc io.ReadCloser
	var err error
	switch alg {
	default:
		return nil, errors.New("unknown compression algorithm")
	case NoCompression:
		rc = io.NopCloser(r)
	case Flate:
		rc = flate.NewReader(r)
	case Gzip:
		rc, err = gzip.NewReader(r)
	case Zlib:
		rc, err = zlib.NewReader(r)
	}
	if err != nil {
		return nil, err
	}
	return decompressor{rc}, nil
}

// decompressor is a wrapper around ReadCloser compressor that calls Close after EOF.
type decompressor struct {
	rc io.ReadCloser
}

func (d decompressor) Read(p []byte) (n int, err error) {
	n, err = d.rc.Read(p)
	if err == io.EOF {
		err1 := d.rc.Close()
		if err1 != nil {
			err = err1
		}
	}
	return
}
