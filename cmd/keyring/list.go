package keyring

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
)

type KeysetEntry struct {
	ID       string
	FP       quark.Fingerprint
	Identity quark.Identity
	Scheme   quark.Scheme
}

func List(secrets bool) ([]KeysetEntry, error) {
	fs := storage.PublicFS()
	if secrets {
		fs = storage.PrivateFS()
	}
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]KeysetEntry, 0, len(dir))
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		f, err := fs.Open(entry.Name())
		if err != nil {
			return nil, err
		}

		tag, v, err := pack.Unpack(f)
		f.Close()
		if err != nil {
			return nil, err
		}

		var pub *quark.Public
		switch tag {
		case pack.TagPublicKeyset:
			pub = v.(*quark.Public)
		case pack.TagPrivateKeyset:
			pub = v.(*quark.Private).Public()
		default:
			return nil, errors.New(f.Name() + " does not contain a keyset")
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
