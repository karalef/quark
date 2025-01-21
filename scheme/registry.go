package scheme

import (
	"errors"
)

// Registry represents a registry of schemes.
type Registry[T Scheme] interface {
	// Register registers a scheme.
	Register(scheme T)

	// ByName returns a scheme by name.
	// Returns an ErrUnknownScheme if the scheme is not registered.
	ByName(name string) (T, error)

	// ListNames returns all registered scheme names.
	ListNames() []string

	// List returns all registered schemes.
	List() []T
}

// ErrUnknownScheme can be returned when the requested scheme is not registered.
var ErrUnknownScheme = errors.New("unknown scheme")

var _ Registry[Scheme] = Map[Scheme]{}

// Map is a base type for schemes map.
// Names are stored in uppercase.
type Map[T Scheme] map[string]T

// Register registers a scheme.
// Panics if the scheme is already registered.
func (schemes Map[T]) Register(scheme T) {
	name := Normalize(scheme.Name())
	if _, ok := schemes[name]; ok {
		panic("scheme " + name + " already registered")
	}
	schemes[name] = scheme
}

// ByName returns a scheme by name.
func (schemes Map[T]) ByName(name string) (T, error) {
	s, ok := schemes[Normalize(name)]
	if !ok {
		return s, ErrUnknownScheme
	}
	return s, nil
}

// ListNames returns all registered scheme names.
func (schemes Map[T]) ListNames() []string {
	all := make([]string, 0, len(schemes))
	for _, s := range schemes {
		all = append(all, s.Name())
	}
	return all
}

// List returns all registered schemes.
func (schemes Map[T]) List() []T {
	all := make([]T, 0, len(schemes))
	for _, v := range schemes {
		all = append(all, v)
	}
	return all
}
