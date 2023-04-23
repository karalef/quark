package keyring

import (
	"io"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/karalef/wfs"
)

// keyset file extensions
const (
	PublicFileExt  = ".qpk"
	PrivateFileExt = ".qsk"
)

// PublicFileName returns the name of a public keyset file.
func PublicFileName(name string) string {
	return name + PublicFileExt
}

// PrivateFileName returns the name of a private keyset file.
func PrivateFileName(name string) string {
	return name + PrivateFileExt
}

// createFile creates a new WRONLY file and returns error if it already exists.
func createFile(fs wfs.Filesystem, name string) (wfs.File, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func writeKeyset[T any](fs wfs.Filesystem, name string, v T, packer func(io.Writer, T) error) error {
	f, err := createFile(fs, name)
	if err != nil {
		return err
	}
	defer f.Close()
	return packer(f, v)
}

func writePub(k *quark.Public) error {
	return writeKeyset(storage.PublicFS(), PublicFileName(k.ID().String()), k, pack.Public)
}

func writePriv(k *quark.Private) error {
	return writeKeyset(storage.PrivateFS(), PrivateFileName(k.ID().String()), k, pack.Private)
}

func readKeyset[T *quark.Public | *quark.Private](fs wfs.Filesystem, name string, tag pack.Tag) (t T, err error) {
	f, err := fs.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	return pack.DecodeExact[T](f, tag)
}

func readPub(id string) (*quark.Public, error) {
	return readKeyset[*quark.Public](storage.PublicFS(), PublicFileName(id), pack.TagPublicKeyset)
}

func readPriv(id string) (*quark.Private, error) {
	return readKeyset[*quark.Private](storage.PrivateFS(), PrivateFileName(id), pack.TagPrivateKeyset)
}
