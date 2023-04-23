package keyring

import (
	"github.com/karalef/quark"
)

func ImportPublic(k *quark.Public) error {
	return writePub(k)
}

func ImportPrivate(ks *quark.Private) error {
	err := ImportPublic(ks.Public())
	if err != nil {
		return err
	}

	return writePriv(ks)
}
