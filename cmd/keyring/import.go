package keyring

import (
	"github.com/karalef/quark"
)

// ImportPublic imports a public keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func ImportPublic(pub quark.Public) error {
	return writePub(true, pub)
}

// ImportPrivate imports a private keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func ImportPrivate(priv quark.Private) error {
	err := ImportPublic(priv.Public())
	if err != nil {
		return err
	}
	return writePriv(true, priv, PassphraseProvider)
}
