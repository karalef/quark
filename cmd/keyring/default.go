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
// If id is empty string, it removes the link.
func SetDefault(id string) error {
	if id == "" {
		return removeDefault()
	}
	privs := storage.Private()
	name := PrivateFileName(id)
	_, err := privs.Stat(name)
	if err != nil {
		return err
	}

	err = removeDefault()
	if err != nil {
		return err
	}

	return privs.Symlink(name, defaultKeysetFile)
}

func removeDefault() error {
	err := storage.Private().Remove(defaultKeysetFile)
	if os.IsNotExist(err) {
		err = nil
	}
	return err
}

// IsDefault returns true if the specified keyset is default.
func IsDefault(id string) (bool, error) {
	path, err := storage.Private().Readlink(defaultKeysetFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	path = filepath.Base(path)
	return path[:len(path)-len(filepath.Ext(path))] == id, nil
}

// ErrNoDefaultKeyset is returned if no default keyset has been set.
var ErrNoDefaultKeyset = errors.New("no default keyset has been set")

// Default returns the default keyset.
// If no default keyset has been set it returns ErrNoDefaultKeyset.
func Default() (*quark.Private, error) {
	priv, err := readPriv(defaultKeysetFile)
	if os.IsNotExist(err) {
		err = ErrNoDefaultKeyset
	}
	return priv, err
}
