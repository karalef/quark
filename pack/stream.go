package pack

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"

	"github.com/karalef/quark/internal"
	"github.com/vmihailenco/msgpack/v5"
)

// Stream represents an de/encodable bytes stream.
type Stream struct {
	// Reader represents the data to be encoded.
	Reader io.Reader

	// Writer represents the decoded data output.
	Writer io.Writer

	writerWrapper func(io.WriteCloser) io.WriteCloser
	readerWrapper func(io.Reader) io.Reader
}

// WrapWriter wraps the encoder's writer.
func (s *Stream) WrapWriter(f func(io.WriteCloser) io.WriteCloser) {
	s.writerWrapper = f
}

// WrapReader wraps the decoder's reader.
func (s *Stream) WrapReader(f func(io.Reader) io.Reader) {
	s.readerWrapper = f
}

// EncodeMsgpack implements msgpack.CustomEncoder.
func (s Stream) EncodeMsgpack(enc *msgpack.Encoder) error {
	w := internal.NopCloser(enc.Writer())
	if s.writerWrapper != nil {
		w = s.writerWrapper(w)
	}
	sw := newStreamWriter(w)
	_, err := io.Copy(sw, s.Reader)
	if err != nil {
		return err
	}
	if err := sw.Close(); err != nil {
		return errors.Join(err, w.Close())
	}
	return w.Close()
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (s *Stream) DecodeMsgpack(dec *msgpack.Decoder) error {
	if s.Writer == nil {
		return errors.New("pack: Stream.Writer is nil")
	}
	r := dec.Buffered()
	if s.readerWrapper != nil {
		r = s.readerWrapper(r)
	}
	_, err := io.Copy(s.Writer, newStreamReader(r))
	return err
}

func newStreamWriter(w io.Writer) *streamWriter {
	return &streamWriter{
		w: w,
	}
}

func newStreamReader(r io.Reader) *streamReader {
	var br byteReader
	if b, ok := r.(byteReader); ok {
		br = b
	} else {
		br = bufio.NewReader(r)
	}
	return &streamReader{
		r: br,
	}
}

var _ io.WriteCloser = (*streamWriter)(nil)

type streamWriter struct {
	w      io.Writer
	length [binary.MaxVarintLen64]byte
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := binary.PutVarint(sw.length[:], int64(len(p)))
	_, err := sw.w.Write(sw.length[:n])
	if err != nil {
		return 0, err
	}
	return sw.w.Write(p)
}

func (sw *streamWriter) Close() error {
	sw.length[0] = 0
	_, err := sw.w.Write(sw.length[:1])
	return err
}

type byteReader interface {
	io.Reader
	io.ByteReader
}

type streamReader struct {
	r         byteReader
	remaining int64
	eof       bool
}

func (sr *streamReader) readLen() (err error) {
	sr.remaining, err = binary.ReadVarint(sr.r)
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return
	}
	if sr.remaining < 0 {
		err = errors.New("negative length")
	} else if sr.remaining == 0 {
		sr.eof = true
		err = io.EOF
	}
	return
}

func (sr *streamReader) Read(p []byte) (n int, err error) {
	if sr.eof {
		return 0, io.EOF
	}
	if sr.remaining < 1 {
		err = sr.readLen()
		if err != nil {
			return
		}
	}

	toRead := int64(len(p))
	if toRead > sr.remaining {
		toRead = sr.remaining
	}

	n, err = io.ReadFull(sr.r, p[:toRead])
	if err == io.EOF && int64(n) != toRead {
		err = io.ErrUnexpectedEOF
	}
	sr.remaining -= int64(n)
	return
}
