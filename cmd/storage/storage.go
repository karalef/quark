package storage

import (
	"errors"
	"fmt"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/pack"
)

// Key represents a key.
type Key interface {
	ID() crypto.ID
	pack.Packable
	*quark.PublicKey[crypto.Key] | *quark.PrivateKey[crypto.Key]
}

// Pubring represents a public key storage.
type Pubring = Storage[crypto.ID, *quark.PublicKey[crypto.Key]]

// Secrets represents a secret key storage.
type Secrets = Storage[crypto.ID, *quark.PrivateKey[crypto.Key]]

// Object represents an object.
type Object[ID fmt.Stringer] interface {
	ID() ID
	pack.Packable
}

// Storage represents a storage.
type Storage[ID fmt.Stringer, T Object[ID]] interface {
	// ByID returns an object by ID.
	// Returns ErrNotFound if the object doesn't exist.
	ByID(ID) (T, error)

	// IsExists returns true if the object exists.
	IsExists(ID) (bool, error)

	// Count returns the number of stored objects.
	Count() (uint, error)

	// Store stores an object.
	// Returns ErrExists if the object already exists.
	Store(T) error

	// Update updates an object.
	// Returns ErrNotFound if the object doesn't exist.
	Update(T) error

	// Delete deletes an object.
	// Returns ErrNotFound if the object doesn't exist.
	Delete(ID) error

	// VisitAll visits all objects.
	VisitAll(func(T) (stop bool, err error)) error
}

// storage errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrExists        = errors.New("already exists")
	ErrInvalidObject = errors.New("invalid object")
)
