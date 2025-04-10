package mac

import (
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
)

// State represent MAC state.
type State interface {
	// Write never returns an error.
	// Some implementations may panic if called after Tag.
	io.Writer

	// Tag appends the current tag to b and returns the resulting slice.
	// It does not change the underlying state.
	Tag(b []byte) []byte

	// Reset resets the MAC to its initial state.
	Reset()

	// Size returns the number of bytes Tag will append.
	Size() int

	// BlockSize returns the MAC's underlying block size.
	// The Write method must be able to accept any amount
	// of data, but it may operate more efficiently if all writes
	// are a multiple of the block size.
	BlockSize() int
}

// Equal compares two Tags for equality without leaking timing information.
func Equal(tag1, tag2 []byte) bool {
	return crypto.Equal(tag1, tag2)
}

// Verify checks that the tag is correct.
func Verify(s State, tag []byte) error {
	if !Equal(tag, s.Tag(nil)) {
		return ErrMismatch
	}
	return nil
}

// ErrMismatch is returned when the Tags do not match.
var ErrMismatch = errors.New("MAC tags do not match")
