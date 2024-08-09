package keystore

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/encaps"
)

type contextKey struct{}

// ContextKey is the context key.
var ContextKey = contextKey{}

// Keystore represents a keys storage.
type Keystore interface {
	ByID(quark.ID) (quark.Identity, error)
	Find(string) (quark.Identity, error)
	KeyByID(quark.ID) (quark.PublicKey, error)
	PrivKeyByID(quark.ID) (quark.PrivateKey, error)
	EncryptionKeyByID(quark.ID) (encaps.PublicKey, error)
	PrivEncryptionKeyByID(quark.ID) (encaps.PrivateKey, error)
	List(filter string) ([]quark.Identity, error)
	Delete(quark.ID) error
	Store(quark.Identity) error
	Import(quark.Identity, quark.PrivateKey) error
	ImportPrivate(quark.PrivateKey) error
}

// ErrExists is returned if the key already exists.
var ErrExists = errors.New("key already exists")

// ErrNotFound is returned when a key is not found.
var ErrNotFound = errors.New("key not found")

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
