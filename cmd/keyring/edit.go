package keyring

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
)

// Edit edits a keyset.
func Edit(query string, id quark.Identity) (quark.Public, error) {
	priv, err := FindPrivate(query)
	if err != nil {
		return nil, err
	}

	old := priv.Identity()
	if id.Name == "" {
		id.Name = old.Name
	}
	if id.Email == "" {
		id.Email = old.Email
	}
	if id.Comment == "" {
		id.Comment = old.Comment
	}

	err = priv.ChangeIdentity(id)
	if err != nil {
		return priv.Public(), err
	}

	err = editKeyset(storage.Private(), PrivateFileName(priv.ID().String()), priv)
	if err != nil {
		return priv.Public(), err
	}
	err = editKeyset(storage.Public(), PublicFileName(priv.ID().String()), priv.Public())
	if err != nil {
		return priv.Public(), err
	}
	return priv.Public(), err
}

func editKeyset(fs storage.FS, name string, ks quark.Keyset) error {
	f, err := fs.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Pack(f, ks)
}
