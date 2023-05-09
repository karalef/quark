package keyring

import (
	"os"

	"github.com/karalef/quark/cmd/storage"
)

// Delete finds keyset by ID, owner name or email and deletes it.
// It return ErrNotFound if the keyset is not found.
func Delete(query string) (id string, err error) {
	ks, err := Find(query)
	if err != nil {
		return "", err
	}

	id = ks.ID().String()

	if def, err := IsDefault(id); err != nil {
		return id, err
	} else if def {
		_, err = SetDefault("")
		if err != nil {
			return id, err
		}
	}
	err = storage.Private().Remove(PrivateFileName(id))
	if err != nil && !os.IsNotExist(err) {
		return id, err
	}

	return id, storage.Public().Remove(PublicFileName(id))
}
