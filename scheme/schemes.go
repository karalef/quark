package scheme

import (
	"errors"
	"strings"
)

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

func (schemes Schemes[T]) ByName(name string) (T, error) {
	s, ok := schemes[strings.ToUpper(name)]
	if !ok {
		return s, ErrUnknownScheme
	}
	return s, nil
}

func (schemes Schemes[T]) ListAll() []string {
	all := make([]string, 0, len(schemes))
	for _, s := range schemes {
		all = append(all, s.Name())
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
