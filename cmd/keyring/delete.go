package keyring

import (
	"github.com/karalef/quark/cmd/storage"
)

// Delete finds keyset by ID, owner name or email and deletes it.
// It return ErrNotFound if the keyset is not found.
func Delete(query string) (id string, err error) {
	priv, err := FindPrivate(query)
	if err != nil && err != ErrNotFound {
		return "", err
	}
	if err == nil {
		id = priv.ID().String()
		err = storage.PrivateFS().Remove(PrivateFileName(id))
		if err != nil {
			return id, err
		}

		// fast way
		return id, storage.PublicFS().Remove(PublicFileName(id))
	}

	pub, err := Find(query)
	if err != nil {
		return "", err
	}

	id = pub.ID().String()
	return id, storage.PublicFS().Remove(PublicFileName(id))
}
