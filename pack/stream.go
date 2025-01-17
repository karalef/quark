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
	W      io.WriteCloser // if set, represents wrapped encodable stream.

	// Writer represents the decoded data output.
	Writer io.Writer
	R      io.Reader // if set, represents wrapped decodable stream.
}

// Read provides the io.Reader interface to wrap the decodable stream.
// Call before decoding causes stack overflow or nil pointer dereference.
func (s *Stream) Read(p []byte) (int, error) { return s.R.Read(p) }

// Write provides the io.Writer interface to wrap the encodable stream.
// Call before encoding causes stack overflow or nil pointer dereference.
func (s *Stream) Write(p []byte) (int, error) { return s.W.Write(p) }

// EncodeMsgpack implements msgpack.CustomEncoder.
func (s *Stream) EncodeMsgpack(enc *Encoder) error {
	if s.Reader == nil {
		return errors.New("pack: Stream.Reader is nil")
	}
	writer := s.W
	sw := &streamWriter{w: enc.Writer()}
	if writer == nil {
		writer = sw
	}
	s.W = sw
	_, err := io.Copy(writer, s.Reader)
	if err != nil {
		return err
	}
	if writer != sw {
		return errors.Join(writer.Close(), sw.Close())
	}
	return sw.Close()
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (s *Stream) DecodeMsgpack(dec *Decoder) error {
	if s.Writer == nil {
		return errors.New("pack: Stream.Writer is nil")
	}
	br, ok := dec.Buffered().(byteReader)
	if !ok {
		br = bufio.NewReader(dec.Buffered())
	}
	reader := s.R
	sr := &streamReader{r: br}
	if reader == nil {
		reader = sr
	}
	s.R = sr
	_, err := io.Copy(s.Writer, reader)
	if err != nil {
		return err
	}
	if sr.eof && sr == reader {
		return nil
	}
	return sr.Close()
}

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

func (sr *streamReader) Close() error {
	if sr.remaining > 0 {
		return errors.New("pack.Stream: decoder stream has remaining bytes")
	}
	if err := sr.readLen(); err != io.EOF {
		return errors.New("pack.Stream: decoder stream was not fully read")
	}
	return nil
}
