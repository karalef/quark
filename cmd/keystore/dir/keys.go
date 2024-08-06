package dir

import (
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
)

func readKeyset[T quark.Keyset](fs storage.FS, name string, opts ...pack.UnpackOption) (t T, err error) {
	f, err := fs.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	return pack.UnpackExact[T](f, opts...)
}

func readPub(name string) (quark.Public, error) {
	return readKeyset[quark.Public](storage.Public(), name)
}

func readPriv(name string) (quark.Private, error) {
	return readKeyset[quark.Private](storage.Private(), name, pack.WithPassphrase(PassphraseProvider))
}

func readPrivWithPassphrase(name string) (string, quark.Private, error) {
	var passphrase string
	provider := func() (string, error) {
		p, err := PassphraseProvider()
		if err == nil {
			passphrase = p
		}
		return p, err
	}
	priv, err := readKeyset[quark.Private](storage.Private(), name, pack.WithPassphrase(provider))
	return passphrase, priv, err
}

// writeKeyset opens or creates a new WRONLY file and writes the keyset to it.
// It returns ErrAlreadyExists if the file already exists and excl is true.
func writeKeyset(fs storage.FS, name string, excl bool, ks quark.Keyset, passphrase Passphrase) error {
	flag := os.O_CREATE | os.O_WRONLY
	if excl {
		flag |= os.O_EXCL
	}
	f, err := fs.OpenFile(name, flag, 0600)
	if err != nil {
		if os.IsExist(err) {
			return ErrAlreadyExists
		}
		return err
	}
	defer f.Close()
	var opts []pack.Option
	if passphrase != nil {
		p, err := passphrase()
		if err != nil {
			return err
		}
		if p != "" {
			opts = []pack.Option{pack.WithEncryption(p, nil)}
		}
	}
	return pack.Pack(f, ks, opts...)
}

func writePub(excl bool, pub quark.Public) error {
	return writeKeyset(storage.Public(), PublicFileName(pub.ID().String()), excl, pub, nil)
}

func writePriv(excl bool, priv quark.Private, passphrase Passphrase) error {
	if passphrase == nil {
		passphrase = PassphraseProvider
	}
	return writeKeyset(storage.Private(), PrivateFileName(priv.ID().String()), excl, priv, passphrase)
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

// loadEntries loads keys ids from storage.
func (ks *dirKeystore) loadEntries(secrets bool) ([]string, error) {
	dir, err := ks.loadDir(secrets)
	if err != nil {
		return nil, err
	}

	ext := ks.cfg.PublicFileExt
	if secrets {
		ext = ks.cfg.PrivateFileExt
	}
	for i, entry := range dir {
		dir[i] = entry[:len(entry)-len(ext)]
	}
	return dir, nil
}

func (ks *dirKeystore) loadDir(private bool) ([]string, error) {
	fs := ks.pubs
	ext := ks.cfg.PublicFileExt
	if private {
		fs = ks.priv
		ext = ks.cfg.PrivateFileExt
	}
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, len(dir))
	for _, entry := range dir {
		if !entry.Type().IsRegular() {
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

func findPrivate(query string) (filename string, err error) {
	pub, err := Find(query)
	if err != nil {
		return "", err
	}
	return PrivateFileName(pub.ID().String()), nil
}

// FindPrivate finds private keyset by id, owner name or email.
// It return ErrNotFound if the keyset is not found.
func FindPrivate(query string) (quark.Private, error) {
	name, err := findPrivate(query)
	if err != nil {
		return nil, err
	}
	return readPriv(name)
}
