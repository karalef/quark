package keyring

import (
	"github.com/karalef/quark"
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
	entries, err := listEntries(secrets)
	if err != nil {
		return nil, err
	}
	list := make([]KeysetEntry, 0, len(entries))
	for _, entry := range entries {
		pub, err := readPub(entry)
		if err != nil {
			return nil, err
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

// listEntries returns public keyset file names.
func listEntries(secrets bool) ([]string, error) {
	dir, err := loadDir(secrets)
	if err != nil {
		return nil, err
	}
	if secrets {
		for i, entry := range dir {
			dir[i] = PublicFileName(entry[:len(entry)-len(PrivateFileExt)])
		}
	}
	return dir, nil
}
