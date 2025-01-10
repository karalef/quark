package armor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

// armor parameters.
const (
	MaxLineLength = 96
)

// A Block represents an armored structure.
//
// The encoded form is:
//
//	-----BEGIN Type-----
//	Headers
//
//	base64raw-encoded Bytes
//	-----END Type-----
//
// where Headers is a possibly empty sequence of Key: Value lines.
type Block struct {
	Type   string            // The type, taken from the preamble.
	Header map[string]string // Optional headers.
	Body   io.Reader         // A Reader from which the contents can be read.
}

// Corrupt is returned when the armor is invalid.
var Corrupt = errors.New("armor invalid")

const (
	eBegin = "-----BEGIN "
	eEnd   = "-----END "
	eol    = "-----"
)

type lineReader struct {
	in  *bufio.Reader
	buf []byte
	eof bool
}

func (l *lineReader) Read(p []byte) (n int, err error) {
	if l.eof {
		return 0, io.EOF
	}

	if len(l.buf) > 0 {
		n = copy(p, l.buf)
		l.buf = l.buf[n:]
		return
	}

	line, isPrefix, err := l.in.ReadLine()
	if err != nil {
		return
	}
	if isPrefix {
		return 0, Corrupt
	}
	if bytes.HasPrefix(line, []byte(eEnd)) {
		l.eof = true
		return 0, io.EOF
	}

	if len(line) > MaxLineLength {
		return 0, Corrupt
	}

	n = copy(p, line)
	bytesToSave := len(line) - n
	if bytesToSave > 0 {
		if cap(l.buf) < bytesToSave {
			l.buf = make([]byte, 0, bytesToSave)
		}
		l.buf = l.buf[0:bytesToSave]
		copy(l.buf, line[n:])
	}

	return
}

// Decode reads an armored block from the given Reader. It will ignore leading
// garbage. If it doesn't find a block, it will return nil, io.EOF. The given
// Reader is not usable after calling this function: an arbitrary amount of data
// may have been read past the end of the block.
func Decode(in io.Reader) (p *Block, err error) {
	r := bufio.NewReaderSize(in, 100)
	var line []byte
	ignoreNext := false

TryNextBlock:
	p = nil

	for {
		ignoreThis := ignoreNext
		line, ignoreNext, err = r.ReadLine()
		if err != nil {
			return
		}
		if ignoreNext || ignoreThis {
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) > len(eBegin)+len(eol) && bytes.HasPrefix(line, []byte(eBegin)) {
			break
		}
	}

	p = new(Block)
	p.Type = string(line[len(eBegin) : len(line)-len(eol)])
	p.Header = make(map[string]string)
	nextIsContinuation := false
	var lastKey string

	for {
		isContinuation := nextIsContinuation
		line, nextIsContinuation, err = r.ReadLine()
		if err != nil {
			p = nil
			return
		}
		if isContinuation {
			p.Header[lastKey] += string(line)
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			break
		}

		i := bytes.Index(line, []byte(": "))
		if i == -1 {
			goto TryNextBlock
		}
		lastKey = string(line[:i])
		p.Header[lastKey] = string(line[i+2:])
	}

	p.Body = base64.NewDecoder(base64.RawStdEncoding, &lineReader{in: r})

	return
}

// Determine determines if an input is an armored block.
// It returns multireader with peeked data.
func Determine(in io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, len(eBegin))
	n, err := io.ReadFull(in, buf)
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	in = io.MultiReader(bytes.NewReader(buf[:n]), in)
	return string(buf[:n]) == eBegin, in, err
}

// Dearmor determines if an input is an armored block and decodes it.
// If the input is not an armored block, it returns the block with the only
// Body field.
func Dearmor(in io.Reader) (*Block, error) {
	armored, in, err := Determine(in)
	if err != nil {
		return nil, err
	}

	if !armored {
		return &Block{Body: in}, nil
	}

	return Decode(in)
}
