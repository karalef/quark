package stream

import "github.com/karalef/quark/crypto/hash"

// NewBuffer returns a new buffer for streaming.
func NewBuffer(initSize int) hash.Scheme { return Buffer{initSize} }

var _ hash.Scheme = Buffer{}

// Buffer represents the hash.Scheme and provides a buffer for streaming.
type Buffer struct {
	InitSize int
}

func (Buffer) Name() string      { return "" }
func (Buffer) Size() int         { return -1 }
func (Buffer) BlockSize() int    { return -1 }
func (b Buffer) New() hash.State { return newBuffer(b.InitSize) }

func newBuffer(initSize int) hash.State {
	if initSize <= 0 {
		initSize = 1024
	}
	b := make([]byte, 0, initSize)
	return (*buffer)(&b)
}

type buffer []byte

func (b *buffer) Write(p []byte) (n int, err error) {
	*b = append(*b, p...)
	return len(p), nil
}

func (b *buffer) Reset()              { *b = (*b)[:0] }
func (b *buffer) Sum(s []byte) []byte { return append(s, *b...) }
func (b *buffer) Size() int           { return -1 }
func (b *buffer) BlockSize() int      { return -1 }
