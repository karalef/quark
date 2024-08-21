package keystore

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/bind"
	"github.com/karalef/quark/encaps"
	"github.com/urfave/cli/v2"
)

type contextKey struct{}

// ContextKey is the context key.
var ContextKey = contextKey{}

func FromContext(c *cli.Context) Keystore {
	return c.Context.Value(ContextKey).(Keystore)
}

type PrivateStore interface {
	StoreSign(*quark.EncryptedKey) error
}

// Keystore represents a keys storage.
type Keystore interface {
	ByID(quark.ID) (*quark.Identity, error)
	Find(string) (*quark.Identity, error)

	GetPrivate(quark.ID, Passphrase) (*quark.PrivateKey, error)
	GetKEMPrivate(quark.ID, Passphrase) (*encaps.PrivateKey, error)

	FindPriv(string) (*quark.PrivateKey, error)
	FindBindings(quark.BindType) ([]*quark.Binding, error)
	EncryptionKeyByID(quark.ID) (*encaps.PublicKey, error)
	DecryptionKeyByID(quark.ID) (*encaps.PrivateKey, error)
	List(filter string) ([]*quark.Identity, error)
	Delete(quark.ID) error
	Import(*quark.Identity) error
	ImportPrivate(*quark.Identity, *quark.PrivateKey) error
	StorePrivate(*quark.PrivateKey) error
}

// ErrExists is returned if the key already exists.
var ErrExists = errors.New("key already exists")

// ErrNotFound is returned when a key is not found.
var ErrNotFound = errors.New("key not found")

// Passphrase represents a function that called to request a passphrase.
type Passphrase func() (string, error)

// DeleteByString deletes a key by string query.
func DeleteByString(ks Keystore, query string) (id quark.ID, err error) {
	key, err := ks.Find(query)
	if err != nil {
		return id, err
	}
	id = key.ID()
	return id, ks.Delete(id)
}

func FindKEMPublicKey(ks Keystore, query string) (*encaps.PublicKey, error) {
	key, err := ks.FindBindings(bind.TypeKEMKey)
	if err != nil {
		return nil, err
	}
	for _, k := range key {
		if k.ID().String() == query {
			return k.PublicKey(), nil
		}
	}
	return nil, ErrNotFound
}
