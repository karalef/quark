package internal

import (
	"errors"
	"strings"
)

// Scheme interface.
type Scheme interface {
	Name() string
}

// CompleteSchemeName combines scheme names.
func CompleteSchemeName(subSchemes ...Scheme) string {
	l := 0
	for _, s := range subSchemes {
		l += len(s.Name())
	}
	b := strings.Builder{}
	b.Grow(l + len(subSchemes) - 1)

	for i, s := range subSchemes {
		b.WriteString(strings.ToUpper(s.Name()))
		if i < len(subSchemes)-1 {
			b.WriteByte('-')
		}
	}

	return b.String()
}

// SplitSchemeName splits scheme names.
func SplitSchemeName(scheme string) []string {
	return strings.Split(scheme, "-")
}

// ErrUnknownScheme can be returned when the requested scheme is not registered.
var ErrUnknownScheme = errors.New("unknown scheme")

// Schemes is a base type for schemes map.
// Names are stored in uppercase.
type Schemes[T Scheme] map[string]T

func (schemes Schemes[T]) Register(scheme T) {
	name := strings.ToUpper(scheme.Name())
	if _, ok := schemes[name]; ok {
		panic("scheme " + name + " already registered")
	}
	schemes[name] = scheme
}

func (schemes Schemes[T]) ByName(name string) T {
	return schemes[strings.ToUpper(name)]
}

func (schemes Schemes[T]) ListAll() []string {
	all := make([]string, 0, len(schemes))
	for k := range schemes {
		all = append(all, k)
	}
	return all
}

func (schemes Schemes[T]) ListSchemes() []T {
	all := make([]T, 0, len(schemes))
	for _, v := range schemes {
		all = append(all, v)
	}
	return all
}
