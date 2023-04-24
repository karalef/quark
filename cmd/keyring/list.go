package keyring

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
)

// KeysetEntry contains general keyset info.
type KeysetEntry struct {
	ID       string
	FP       quark.Fingerprint
	Identity quark.Identity
	Scheme   quark.Scheme
}

// List lists all keysets.
func List(secrets bool) ([]KeysetEntry, error) {
	fs := storage.Public()
	if secrets {
		fs = storage.Private()
	}
	dir, err := loadDir(fs)
	if err != nil {
		return nil, err
	}
	list := make([]KeysetEntry, 0, len(dir))
	for _, entry := range dir {
		var pub *quark.Public
		if secrets {
			var priv *quark.Private
			priv, err = readPriv(entry)
			pub = priv.Public()
		} else {
			pub, err = readPub(entry)
		}

		list = append(list, KeysetEntry{
			ID:       pub.ID().String(),
			FP:       pub.Fingerprint(),
			Identity: pub.Identity(),
			Scheme:   pub.Scheme(),
		})
	}
	return list, err
}
