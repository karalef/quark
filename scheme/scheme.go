package scheme

import (
	"errors"
	"strings"

	"github.com/karalef/quark/pack"
)

// Scheme interface.
type Scheme interface {
	Name() string
}

const (
	// Delimeter is used to separate scheme names.
	Delimeter = '-'
)

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
		b.WriteString(strings.ToUpper(name))
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

// StringName implements the Scheme interface and can be msgpack en/decoded.
type StringName string

// Name returns the scheme name.
func (n StringName) Name() string { return string(n) }

// EncodeMsgpack implements pack.CustomEncoder.
func (n StringName) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(string(n))
}

// DecodeMsgpack implements pack.CustomDecoder.
func (n *StringName) DecodeMsgpack(dec *pack.Decoder) error {
	s, err := dec.DecodeString()
	if err != nil {
		return err
	}
	*n = StringName(s)
	return nil
}
