package keys

import (
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/karalef/wfs"
)

func FP(ks quark.PublicKeyset) string {
	return quark.FingerprintOf(ks).String()
}

func IDByFP(fp quark.Fingerprint) string {
	return quark.KeysetIDByFP(fp).String()
}

func IDOf(ks quark.PublicKeyset) string {
	return quark.KeysetIDOf(ks).String()
}

func UsePublic(keysetID string) (quark.PublicKeyset, error) {
	f, err := storage.PublicKeysFS().Open(pubFileName(keysetID))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return pack.UnpackPublic(f)
}

func UsePrivate(keysetID string) (quark.PrivateKeyset, error) {
	f, err := storage.PrivateKeysFS().Open(privFileName(keysetID))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return pack.UnpackPrivate(f)
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
	return findFile(storage.PrivateKeysFS(), id, privKeysetExt)
}

func findPublic(id string) (string, error) {
	return findFile(storage.PublicKeysFS(), id, pubKeysetExt)
}
