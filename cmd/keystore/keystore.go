package keystore

import (
	"errors"

	"github.com/karalef/quark"
)

type contextKey struct{}

// ContextKey is the context key.
var ContextKey = contextKey{}

// Keystore represents a keys storage.
type Keystore interface {
	ByID(quark.ID) (Key, error)
	Find(string) (Key, error)
	List(filter string) ([]Key, error)
	Delete(quark.ID) error
	Store(quark.Keyset) error
	ImportPublic(quark.Public) error
	ImportPrivate(quark.Private) error
}

// ErrExists is returned if the key already exists.
var ErrExists = errors.New("key already exists")

// ErrNotFound is returned when a key is not found.
var ErrNotFound = errors.New("key not found")

// Key represents an interface for an existing key.
type Key interface {
	ID() quark.ID
	Fingerprint() quark.Fingerprint
	Identity() quark.Identity
	Scheme() quark.Scheme
	IsPrivateExists() bool
	Public() (quark.Public, error)
	Private() (quark.Private, error)
}

// Passphrase represents a function that called to request a passphrase.
type Passphrase func() (string, error)

// Match func.
func Match(ks quark.Keyset, query string) bool {
	ident := ks.Identity()
	return ks.ID().String() == query ||
		ident.Name == query ||
		ident.Email == query ||
		ident.Comment == query
}

// DeleteByString deletes a key by string query.
func DeleteByString(ks Keystore, query string) (id quark.ID, err error) {
	key, err := ks.Find(query)
	if err != nil {
		return id, err
	}
	id = key.ID()
	return id, ks.Delete(id)
}
