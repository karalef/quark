package keyring

import (
	"errors"
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
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

// ErrNotFound is returned when a keyset is not found.
var ErrNotFound = errors.New("keyset not found")

func readKeyset[T quark.Keyset](fs storage.FS, name string) (t T, err error) {
	f, err := fs.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	return pack.UnpackExact[T](f)
}

func readPub(name string) (quark.Public, error) {
	return readKeyset[quark.Public](storage.Public(), name)
}

func readPriv(name string) (quark.Private, error) {
	return readKeyset[quark.Private](storage.Private(), name)
}

// ByID returns a keyset by its ID.
func ByID(id string) (quark.Public, error) {
	pub, err := readPub(PublicFileName(id))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return pub, err
}

// ByIDPrivate returns a keyset by its ID.
func ByIDPrivate(id string) (quark.Private, error) {
	priv, err := readPriv(PrivateFileName(id))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return priv, err
}

func isPrivateExists(id string) (bool, error) {
	_, err := storage.Private().Stat(PrivateFileName(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// IsPrivateExists checks if a private keyset exists.
func IsPrivateExists(pub quark.Public) (bool, error) {
	return isPrivateExists(pub.ID().String())
}

func validateFileName(name string, ext string) bool {
	if !strings.HasSuffix(name, ext) {
		return false
	}
	_, ok := quark.IDFromString(name[:len(name)-len(ext)])
	return ok
}

func loadDir(private bool) ([]string, error) {
	fs := storage.Public()
	ext := PublicFileExt
	if private {
		fs = storage.Private()
		ext = PrivateFileExt
	}
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, len(dir))
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !validateFileName(name, ext) {
			continue
		}

		list = append(list, name)
	}
	return list, nil
}

func match(ks quark.Public, query string) bool {
	ident := ks.Identity()
	return ks.ID().String() == query || ident.Name == query || ident.Email == query
}

// Find finds public keyset by id, owner name or email.
// It return ErrNotFound if the keyset is not found.
func Find(query string) (quark.Public, error) {
	if query == "" {
		return nil, ErrNotFound
	}
	entries, err := loadDir(false)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		ks, err := readPub(entry)
		if err != nil {
			return nil, err
		}
		if match(ks, query) {
			return ks, nil
		}
	}
	return nil, ErrNotFound
}

// FindPrivate finds private keyset by id, owner name or email.
// It return ErrNotFound if the keyset is not found.
func FindPrivate(query string) (quark.Private, error) {
	pub, err := Find(query)
	if err != nil {
		return nil, err
	}
	return readPriv(PrivateFileName(pub.ID().String()))
}
