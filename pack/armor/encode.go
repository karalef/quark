package armor

import (
	"encoding/base64"
	"io"
)

// armor parameters.
const (
	LineLength = 64
)

const (
	headerSep = ": "
	newline   = "\n"
	eolOut    = eol + newline
)

var newlineBytes = []byte{'\n'}

// multiWrite writes its arguments to the given Writer.
func multiWrite(out io.Writer, strs ...string) (err error) {
	for _, s := range strs {
		if _, err = io.WriteString(out, s); err != nil {
			return err
		}
	}
	return
}

type lineBreaker struct {
	out         io.Writer
	line        []byte
	length      int
	used        int
	haveWritten bool
}

func newLineBreaker(out io.Writer, length int) *lineBreaker {
	return &lineBreaker{
		length: length,
		line:   make([]byte, length),
		out:    out,
	}
}

func (l *lineBreaker) Write(b []byte) (n int, err error) {
	n = len(b)
	if n == 0 {
		return
	}

	if l.used == 0 && l.haveWritten {
		_, err = l.out.Write(newlineBytes)
		if err != nil {
			return
		}
	}

	if l.used+len(b) < l.length {
		l.used += copy(l.line[l.used:], b)
		return
	}

	l.haveWritten = true
	_, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := l.length - l.used
	l.used = 0

	_, err = l.out.Write(b[0:excess])
	if err != nil {
		return
	}

	_, err = l.Write(b[excess:])
	return
}

func (l *lineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
	}
	return
}

type encoding struct {
	out       io.Writer
	breaker   *lineBreaker
	b64       io.WriteCloser
	blockType string
}

func (e *encoding) Write(data []byte) (n int, err error) {
	return e.b64.Write(data)
}

func (e *encoding) Close() (err error) {
	if err = e.b64.Close(); err != nil {
		return
	}
	e.breaker.Close()

	return multiWrite(e.out, newline, eEnd, e.blockType, eol)
}

// Encode returns a WriteCloser which will encode the data written to it.
func Encode(out io.Writer, blockType string, headers map[string]string) (w io.WriteCloser, err error) {
	if err = multiWrite(out, eBegin, blockType, eolOut); err != nil {
		return
	}

	for k, v := range headers {
		if err = multiWrite(out, k, headerSep, v, newline); err != nil {
			return
		}
	}

	if _, err = out.Write(newlineBytes); err != nil {
		return
	}

	br := newLineBreaker(out, LineLength)
	return &encoding{
		out:       out,
		breaker:   br,
		b64:       base64.NewEncoder(base64.RawStdEncoding, br),
		blockType: blockType,
	}, nil
}
