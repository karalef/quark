package keys

import (
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/wfs"
)

func IDByFP(fp quark.Fingerprint) string {
	return quark.KeysetIDFromFP(fp).String()
}

func UsePublic(keysetID string) (*quark.Public, error) {
	return readPub(storage.PublicFS(), pubFileName(keysetID))
}

func UsePrivate(keysetID string) (*quark.Private, error) {
	return readPriv(storage.PrivateFS(), privFileName(keysetID))
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
	return findFile(storage.PrivateFS(), id, privKeysetExt)
}

func findPublic(id string) (string, error) {
	return findFile(storage.PublicFS(), id, pubKeysetExt)
}
