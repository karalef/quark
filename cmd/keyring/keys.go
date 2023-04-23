package keyring

import (
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/wfs"
)

func UsePublic(keysetID string) (*quark.Public, error) {
	return readPub(keysetID)
}

func UsePrivate(keysetID string) (*quark.Private, error) {
	return readPriv(keysetID)
}

func findFile(fs wfs.Filesystem, id string, ext string) (string, error) {
	dir, err := fs.ReadDir(".")
	if err != nil {
		return "", err
	}
	for _, entry := range dir {
		if strings.TrimSuffix(entry.Name(), ext) == id {
			return entry.Name(), nil
		}
	}
	return "", os.ErrNotExist
}

func findPrivate(id string) (string, error) {
	return findFile(storage.PrivateFS(), id, PrivateFileExt)
}

func findPublic(id string) (string, error) {
	return findFile(storage.PublicFS(), id, PublicFileExt)
}
