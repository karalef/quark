package internal

import "strings"

// Schemes is a base type for schemes map.
// Names are stored in uppercase.
type Schemes[T interface {
	Name() string
}] map[string]T

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
