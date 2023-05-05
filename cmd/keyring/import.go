package keyring

import (
	"errors"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
)

// ErrAlreadyExists is returned if the keyset already exists.
var ErrAlreadyExists = errors.New("keyset already exists")

// writeKeyset creates a new WRONLY file and writes the keyset to it.
// It returns errAlreadyExists if the file already exists.
func writeKeyset[T Keyset](fs storage.FS, name string, ks T) error {
	f, err := fs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return ErrAlreadyExists
		}
		return err
	}
	defer f.Close()
	return pack.Pack(f, ks)
}

// ImportPublic imports a public keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func ImportPublic(pub *quark.Public) error {
	id := pub.ID().String()
	return writeKeyset(storage.Public(), PublicFileName(id), pub)
}

// ImportPrivate imports a private keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func ImportPrivate(priv *quark.Private) error {
	err := ImportPublic(priv.Public())
	if err != nil {
		return err
	}

	id := priv.ID().String()
	return writeKeyset(storage.Private(), PrivateFileName(id), priv)
}
