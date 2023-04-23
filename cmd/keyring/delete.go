package keyring

import (
	"errors"
	"os"

	"github.com/karalef/quark/cmd/storage"
)

func DeleteByID(id string) (found bool, err error) {
	privks, err := findPrivate(id)
	if err != nil && err != os.ErrNotExist {
		return false, err
	}
	if privks != "" {
		err = storage.PrivateFS().Remove(privks)
		if err != nil {
			return true, err
		}
	}

	pubks, err := findPublic(id)
	if err != nil {
		if err == os.ErrNotExist && privks != "" {
			return true, errors.New("private keyset was found but public was not")
		}
		return false, err
	}
	return true, storage.PublicFS().Remove(pubks)
}
