package pack

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// Stream represents an de/encodable bytes stream.
type Stream struct {
	// Reader represents the data to be encoded.
	Reader io.Reader

	// Writer represents the decoded data output.
	Writer io.Writer

	writerWrapper func(io.Writer) io.WriteCloser
	readerWrapper func(io.Reader) io.Reader
}

// WrapWriter wraps the encoder's writer.
func (s *Stream) WrapWriter(f func(io.Writer) io.WriteCloser) {
	s.writerWrapper = f
}

// WrapReader wraps the decoder's reader.
func (s *Stream) WrapReader(f func(io.Reader) io.Reader) {
	s.readerWrapper = f
}

// EncodeMsgpack implements msgpack.CustomEncoder.
func (s Stream) EncodeMsgpack(enc *Encoder) error {
	if s.Reader == nil {
		return errors.New("pack: Stream.Reader is nil")
	}
	sw := newStreamWriter(enc.Writer())
	wc := io.WriteCloser(sw)
	if s.writerWrapper != nil {
		wc = s.writerWrapper(wc)
	}
	_, err := io.Copy(wc, s.Reader)
	if err != nil {
		return err
	}
	if s.writerWrapper != nil {
		err = wc.Close()
	}
	return errors.Join(err, sw.Close())
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (s *Stream) DecodeMsgpack(dec *Decoder) error {
	if s.Writer == nil {
		return errors.New("pack: Stream.Writer is nil")
	}
	sr := newStreamReader(dec.Buffered())
	r := io.Reader(sr)
	if s.readerWrapper != nil {
		r = s.readerWrapper(r)
	}
	_, err := io.Copy(s.Writer, r)
	if err != nil {
		return err
	}
	if s.readerWrapper == nil || sr.eof {
		return nil
	}
	if sr.remaining > 0 {
		return errors.New("pack.Stream: decoder stream has remaining bytes")
	}
	err = sr.readLen()
	if err != io.EOF {
		return errors.New("pack.Stream: decoder stream was not fully read")
	}
	return nil
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
	n := binary.PutUvarint(sw.length[:], uint64(len(p)))
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
	remaining uint64
	eof       bool
}

func (sr *streamReader) readLen() (err error) {
	sr.remaining, err = binary.ReadUvarint(sr.r)
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return
	}
	if sr.remaining == 0 {
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

	toRead := uint64(len(p))
	if toRead > sr.remaining {
		toRead = sr.remaining
	}

	n, err = io.ReadFull(sr.r, p[:toRead])
	if err == io.EOF && uint64(n) != toRead {
		err = io.ErrUnexpectedEOF
	}
	sr.remaining -= uint64(n)
	return
}
