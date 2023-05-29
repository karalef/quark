package keyring

import (
	"github.com/karalef/quark"
)

// List lists all keysets.
func List(secrets bool) ([]quark.KeysetInfo, error) {
	entries, err := listEntries(secrets)
	if err != nil {
		return nil, err
	}
	list := make([]quark.KeysetInfo, 0, len(entries))
	for _, entry := range entries {
		pub, err := readPub(entry)
		if err != nil {
			return nil, err
		}
		list = append(list, pub.Info())
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
