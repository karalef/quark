package keys

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/karalef/wfs"
)

const (
	pubKeysetExt  = ".qpk"
	privKeysetExt = ".qsk"
)

func pubFileName(id string) string {
	return id + pubKeysetExt
}

func privFileName(id string) string {
	return id + privKeysetExt
}

// CreateFile creates a new WRONLY file and returns error if it already exists.
func CreateFile(fs wfs.Filesystem, name string) (wfs.File, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func LoadPublic(keysetID string) (quark.PublicKeyset, error) {
	f, err := storage.PublicKeysFS().Open(pubFileName(keysetID))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return pack.UnpackPublic(f)
}

func LoadPrivavte(keysetID string) (quark.PrivateKeyset, error) {
	f, err := storage.PublicKeysFS().Open(privFileName(keysetID))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return pack.UnpackPrivate(f)
}

func writeFile(fs wfs.Filesystem, name string, v any) error {
	f, err := CreateFile(fs, name)
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Pack(f, v)
}

func writePubPrepacked(fs wfs.Filesystem, k pack.PackedPublic) error {
	return writeFile(fs, pubFileName(quark.KeysetIDByFP(k.Fingerprint).String()), k)
}

func writePrivPrepacked(fs wfs.Filesystem, k pack.PackedPrivate) error {
	return writeFile(fs, privFileName(quark.KeysetIDByFP(k.Fingerprint).String()), k)
}
