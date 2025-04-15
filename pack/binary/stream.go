package binary

import (
	"bufio"
	"encoding/binary"
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

// ChainCloser returns the io.WriteCloser which uses wc to write. Calling the
// Close method will close the wc first and then c. It is useful for wrapping
// the c where the wrapper accepts the io.Writer and does not close it.
func ChainCloser(c io.Closer, wc io.WriteCloser) io.WriteCloser {
	return chainedCloser{c, wc}
}

type chainedCloser struct {
	c io.Closer
	io.WriteCloser
}

func (c chainedCloser) Close() error {
	if err := c.WriteCloser.Close(); err != nil {
		return errors.Join(err, c.c.Close())
	}
	return c.c.Close()
}

// ByteReader is an io.Reader and io.ByteReader interface.
type ByteReader interface {
	io.Reader
	io.ByteReader
}

// WrapEncode is a function that wraps the encoder writer.
type WrapEncode = func(io.Writer) (io.WriteCloser, error)

// WrapDecode is a function that wraps the decoder reader.
type WrapDecode = func(io.Reader) (io.Reader, error)

// NewStream returns a new Stream.
func NewStream(data io.Reader) *Stream { return &Stream{Reader: data} }

// Stream represents a MessagePack de/encodable bytes stream.
// The Reader/Writer field is required for encoding/decoding.
type Stream struct {
	// Reader represents the data to be encoded.
	// It must be not nil while encoding.
	Reader io.Reader

	// W is a message writer. It wraps the stream writer. It is used when some
	// stream algorithm is not implemented to wrap the io.Reader.
	W WrapEncode

	// Writer represents the decoded data output.
	// It must be not nil while decoding.
	Writer io.Writer

	// R is a message reader. It wraps the stream reader. It is used when some
	// stream algorithm is not implemented to wrap the io.Writer.
	R WrapDecode

	// Buffer is the buffer size used for encoding.
	Buffer uint
}

// EncodeMsgpack implements msgpack.CustomEncoder.
func (s Stream) EncodeMsgpack(enc *Encoder) error {
	if s.Reader == nil {
		return errors.New("pack: Stream.Reader is nil")
	}
	var sw io.WriteCloser
	if s.Buffer == 0 {
		sw = NewWriter(enc.Writer())
	} else {
		sw = NewBuffered(enc.Writer(), s.Buffer)
	}
	w, same := sw, true
	if s.W != nil {
		wrapped, err := s.W(sw)
		if err != nil {
			return err
		}
		if wrapped != nil {
			w, same = wrapped, false
		}
	}
	if _, err := io.Copy(w, s.Reader); err != nil {
		return err
	}
	if !same {
		return errors.Join(w.Close(), sw.Close())
	}
	return sw.Close()
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (s *Stream) DecodeMsgpack(dec *Decoder) error {
	if s.Writer == nil {
		return errors.New("pack: Stream.Writer is nil")
	}
	br, ok := dec.Buffered().(ByteReader)
	if !ok {
		br = bufio.NewReader(dec.Buffered())
	}

	sr := NewReader(br)
	r, same := io.Reader(sr), true
	if s.R != nil {
		wrapped, err := s.R(br)
		if err != nil {
			return err
		}
		if wrapped != nil {
			r, same = wrapped, false
		}
	}
	if _, err := io.Copy(s.Writer, r); err != nil {
		return err
	}
	if sr.eof && same {
		return nil
	}
	return sr.Close()
}

// NewBuffered returns a new Buffered.
func NewBuffered(w io.Writer, buf uint) *Buffered {
	if buf == 0 {
		buf = 4096
	}
	return &Buffered{
		out: Writer{out: w},
		buf: make([]byte, buf),
	}
}

// Buffered is a buffered binary writer that puts the length prefix before each
// written chunk.
type Buffered struct {
	out Writer
	buf []byte
}

func (b *Buffered) Write(p []byte) (int, error) {
	l := len(p)
	if l == 0 {
		return 0, nil
	}
	if l > cap(b.buf)-len(b.buf) {
		return l, b.flush(l)
	}
	b.buf = append(b.buf, p...)
	return l, nil
}

func (b *Buffered) flush(addLen int) error {
	err := b.out.writeLen(uint64(len(b.buf) + addLen))
	if err != nil {
		return err
	}
	if _, err = b.out.Write(b.buf); err != nil {
		return err
	}
	b.buf = b.buf[:0]
	return nil
}

func (b *Buffered) Close() error {
	if len(b.buf) > 0 {
		if err := b.flush(0); err != nil {
			return err
		}
	}
	return b.out.Close()
}

// NewWriter returns a new Writer.
func NewWriter(w io.Writer) *Writer { return &Writer{out: w} }

// Writer is a binary writer that puts the length prefix before each written
// chunk.
type Writer struct {
	out io.Writer
	len [binary.MaxVarintLen64]byte
}

func (sw *Writer) writeLen(l uint64) error {
	n := binary.PutUvarint(sw.len[:], l)
	_, err := sw.out.Write(sw.len[:n])
	return err
}

func (sw *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := sw.writeLen(uint64(len(p))); err != nil {
		return 0, err
	}
	return sw.out.Write(p)
}

func (sw *Writer) Close() error {
	sw.len[0] = 0
	_, err := sw.out.Write(sw.len[:1])
	return err
}

// NewReader returns a new Reader.
func NewReader(r ByteReader) *Reader { return &Reader{r: r} }

// Reader is a binary reader that reads the stream created by Writer.
type Reader struct {
	r   ByteReader
	rem uint64
	eof bool
}

func (sr *Reader) readLen() (err error) {
	sr.rem, err = binary.ReadUvarint(sr.r)
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return
	}
	if sr.rem == 0 {
		sr.eof = true
		err = io.EOF
	}
	return
}

func (sr *Reader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := sr.Read(b[:])
	return b[0], err
}

func (sr *Reader) Read(p []byte) (n int, err error) {
	if sr.eof {
		return 0, io.EOF
	}
	if sr.rem < 1 {
		err = sr.readLen()
		if err != nil {
			return
		}
	}

	toRead := uint64(len(p))
	if toRead > sr.rem {
		toRead = sr.rem
	}

	n, err = io.ReadFull(sr.r, p[:toRead])
	if err == io.EOF && uint64(n) != toRead {
		err = io.ErrUnexpectedEOF
	}
	sr.rem -= uint64(n)
	return
}

// Close closes the Reader. Returns an error if the stream was not fully read.
func (sr *Reader) Close() error {
	if sr.eof {
		return nil
	}
	if sr.rem > 0 {
		return errors.New("binary.Reader.Close: stream has remaining bytes")
	}
	if err := sr.readLen(); err != io.EOF {
		return errors.New("binary.Reader.Close: stream was not fully read")
	}
	return nil
}
