package internal

import "strings"

// Scheme interface.
type Scheme interface {
	Name() string
}

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
