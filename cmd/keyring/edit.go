package keyring

import (
	"github.com/karalef/quark"
)

// Edit edits a keyset.
func Edit(query string, id quark.Identity) (quark.Public, error) {
	privName, err := findPrivate(query)
	if err != nil {
		return nil, err
	}

	passphrase, priv, err := readPrivWithPassphrase(privName)
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

	pub := priv.Public()

	err = priv.ChangeIdentity(id)
	if err != nil {
		return pub, err
	}

	err = writePriv(false, priv, func() (string, error) { return passphrase, nil })
	if err != nil {
		return pub, err
	}
	err = writePub(false, pub)
	if err != nil {
		return pub, err
	}
	return pub, err
}
