package mac

import (
	"crypto/subtle"
	"errors"
	"io"
)

// State represent State state.
type State interface {
	// Write never returns an error.
	// Some implementations may panic if called after Tag.
	io.Writer

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(tag1, tag2 []byte) bool {
	return subtle.ConstantTimeCompare(tag1, tag2) == 1
}

// ErrMismatch is returned when the MACs do not match.
var ErrMismatch = errors.New("MACs do not match")
