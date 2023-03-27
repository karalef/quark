package keys

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/pack"
	"github.com/karalef/wfs"
)

const keysetExt = ".qks"

func keysetFileName(keyID string) string {
	return keyID + keysetExt
}

// CreateFile creates a new WRONLY file and returns error if it already exists.
func CreateFile(fs wfs.Filesystem, name string) (wfs.File, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func loadKeyset(f wfs.File) (*pack.PackedKeyset, error) {
	var ks pack.PackedKeyset
	if err := pack.Unpack(f, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

func LoadKey(fs wfs.Filesystem, keyID string) (*pack.PackedKeyset, error) {
	f, err := fs.Open(keysetFileName(keyID))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return loadKeyset(f)
}

func LoadPub(fs wfs.Filesystem, keyID string) (quark.PublicKeyset, error) {
	pks, err := LoadKey(fs, keyID)
	if err != nil {
		return nil, err
	}
	return pks.UnpackPublic()
}

func LoadPriv(fs wfs.Filesystem, keyID string) (quark.PrivateKeyset, error) {
	pks, err := LoadKey(fs, keyID)
	if err != nil {
		return nil, err
	}
	return pks.UnpackPrivate()
}

func WritePubFile(fs wfs.Filesystem, k quark.PublicKeyset) error {
	f, err := CreateFile(fs, keysetFileName(KeyID(k)))
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Public(f, k)
}

func WritePrivFile(fs wfs.Filesystem, k quark.PrivateKeyset) error {
	f, err := CreateFile(fs, keysetFileName(KeyID(k)))
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Private(f, k)
}
