package scheme

import (
	"errors"
	"strings"
)

// Scheme interface.
type Scheme interface {
	Name() string
}

const (
	// Delimeter is used to separate scheme names.
	Delimeter = '-'
)

// Normalize converts scheme name to uppercase.
func Normalize(scheme string) string {
	return strings.ToUpper(scheme)
}

// Join combines scheme names.
func Join(schemes ...Scheme) string {
	return join(schemes, Delimeter)
}

func join(schemes []Scheme, delim byte) string {
	l := 0
	c := len(schemes)
	for _, s := range schemes {
		nl := len(s.Name())
		if nl == 0 {
			c--
		}
		l += nl
	}
	b := strings.Builder{}
	b.Grow(l + c - 1)

	for i, s := range schemes {
		name := s.Name()
		if name == "" {
			continue
		}
		b.WriteString(Normalize(name))
		if i < len(schemes)-1 {
			b.WriteByte(delim)
		}
	}

	return b.String()
}

// Split splits scheme names.
func Split(scheme string) []string {
	return strings.Split(scheme, string(Delimeter))
}

// SplitN is the same as Split, but requires exactly n parts.
func SplitN(scheme string, n uint) ([]string, error) {
	if parts := Split(scheme); uint(len(parts)) == n {
		return parts, nil
	}
	return nil, ErrInvalidScheme
}

// ErrInvalidScheme is returned when scheme is invalid.
var ErrInvalidScheme = errors.New("invalid scheme")

// String implements the Scheme interface.
type String string

// Name returns the scheme name.
func (n String) Name() string { return string(n) }
