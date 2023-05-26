package keyring

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
)

const defaultKeysetFile = "default"

// SetDefault sets the default keyset.
// If query is empty string, it removes the link.
func SetDefault(query string) (string, error) {
	if query == "" {
		return "", removeDefault()
	}
	pub, err := Find(query)
	if err != nil {
		return "", err
	}

	id := pub.ID().String()
	return id, SetDefaultByID(id)
}

// SetDefaultByID sets the default keyset by its ID.
func SetDefaultByID(id string) error {
	if ok, err := isPrivateExists(id); err != nil {
		return err
	} else if !ok {
		return errors.New("private keyset does not exist")
	}

	err := removeDefault()
	if err != nil {
		return err
	}
	return storage.Private().Symlink(PrivateFileName(id), defaultKeysetFile)
}

func removeDefault() error {
	err := storage.Private().Remove(defaultKeysetFile)
	if os.IsNotExist(err) {
		err = nil
	}
	return err
}

func defaultID() (string, error) {
	path, err := storage.Private().Readlink(defaultKeysetFile)
	if err != nil {
		return "", err
	}
	path = filepath.Base(path)
	return path[:len(path)-len(filepath.Ext(path))], nil
}

// IsDefaultExists returns true if the default keyset is set.
func IsDefaultExists() (bool, error) {
	id, err := defaultID()
	if os.IsNotExist(err) {
		return false, nil
	}
	return id != "", err
}

// IsDefault returns true if the specified keyset is default.
func IsDefault(id string) (bool, error) {
	defID, err := defaultID()
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	return defID == id, nil
}

// ErrNoDefaultKeyset is returned if no default keyset has been set.
var ErrNoDefaultKeyset = errors.New("no default keyset has been set")

// Default returns the default keyset.
// If no default keyset has been set it returns ErrNoDefaultKeyset.
func Default() (quark.Private, error) {
	priv, err := readPriv(defaultKeysetFile)
	if os.IsNotExist(err) {
		err = ErrNoDefaultKeyset
	}
	return priv, err
}

// DefaultPublic returns the public part of default keyset.
// If no default keyset has been set it returns ErrNoDefaultKeyset.
func DefaultPublic() (quark.Public, error) {
	defID, err := defaultID()
	if err != nil {
		if os.IsNotExist(err) {
			err = ErrNoDefaultKeyset
		}
		return nil, err
	}
	return ByID(defID)
}
