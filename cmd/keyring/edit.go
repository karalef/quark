package keyring

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
)

// Edit edits a keyset.
func Edit(query string, id quark.Identity) (quark.Public, error) {
	pub, err := Find(query)
	if err != nil {
		return nil, err
	}

	priv, err := ByIDPrivate(pub.ID().String())
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	old := pub.Identity()
	if id.Name == "" {
		id.Name = old.Name
	}
	if id.Email == "" {
		id.Email = old.Email
	}
	if id.Comment == "" {
		id.Comment = old.Comment
	}

	err = quark.ChangeIdentity(pub, id)
	if err != nil {
		return pub, err
	}
	if priv != nil {
		err = quark.ChangeIdentity(priv, id)
		if err != nil {
			return pub, err
		}
	}

	err = editKeyset(storage.Public(), PublicFileName(pub.ID().String()), pub)
	if err != nil {
		return pub, err
	}
	if priv != nil {
		err = editKeyset(storage.Private(), PrivateFileName(priv.ID().String()), priv)
	}
	return pub, err
}

func editKeyset(fs storage.FS, name string, ks quark.Keyset) error {
	f, err := fs.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Pack(f, ks)
}
