package keys

import (
	"io"
	"os"

	"github.com/karalef/quark"
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

func writePub(fs wfs.Filesystem, k *quark.Public, name string) error {
	if name == "" {
		name = pubFileName(k.ID().String())
	}
	return writeKeyset(fs, name, k, pack.Public)
}

func writePriv(fs wfs.Filesystem, k *quark.Private, name string) error {
	if name == "" {
		name = privFileName(k.ID().String())
	}
	return writeKeyset(fs, name, k, pack.Private)
}

func readKeyset[T *quark.Public | *quark.Private](fs wfs.Filesystem, name string, tag pack.Tag) (t T, err error) {
	f, err := fs.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	return pack.DecodeExact[T](f, tag)
}

func readPub(fs wfs.Filesystem, name string) (*quark.Public, error) {
	return readKeyset[*quark.Public](fs, name, pack.TagPublicKeyset)
}

func readPriv(fs wfs.Filesystem, name string) (*quark.Private, error) {
	return readKeyset[*quark.Private](fs, name, pack.TagPrivateKeyset)
}
