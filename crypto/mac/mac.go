package mac

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/karalef/quark/internal"
	"golang.org/x/crypto/poly1305"
)

// State represent State state.
type State interface {
	// Write never returns an error.
	io.Writer

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte

	// Reset resets the MAC to its initial state.
	Reset()
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(tag1, tag2 []byte) bool {
	return subtle.ConstantTimeCompare(tag1, tag2) == 1
}

// CheckKeySize checks the key size.
func CheckKeySize(s Scheme, size int) error {
	fixed, max := s.KeySize(), s.MaxKeySize()
	switch {
	case fixed == 0 && max == 0:
	case fixed != 0:
		if size != fixed {
			return errors.Join(ErrKeySize, errors.New("does not match fixed key size"))
		}
	default:
		if size > max {
			return errors.Join(ErrKeySize, errors.New("exceeds maximum key size"))
		}
	}
	return nil
}

// ErrKeySize is returned when the key size is invalid.
var ErrKeySize = errors.New("invalid key size")

// ErrMismatch is returned when the MACs do not match.
var ErrMismatch = errors.New("MACs do not match")

var Poly1305 = New("Poly1305", 32, 0, 16, 0, func(key []byte) State {
	key = internal.Copy(key)
	m := &macpoly1305{
		key: (*[32]byte)(key),
	}
	m.Reset()
	return m
})

type macpoly1305 struct {
	*poly1305.MAC
	key *[32]byte
}

func (m macpoly1305) Tag(b []byte) []byte { return m.MAC.Sum(b) }
func (m *macpoly1305) Reset()             { m.MAC = poly1305.New(m.key) }
