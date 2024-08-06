package dir

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/cmd/storage"
)

type Config struct {
	Root           string
	PublicDir      string
	PrivateDir     string
	PublicFileExt  string
	PrivateFileExt string
}

// DefaultConfig is the default configuration except the root path.
var DefaultConfig = Config{
	PublicDir:      "public",
	PrivateDir:     "private",
	PublicFileExt:  ".qpk",
	PrivateFileExt: ".qsk",
}

func New(cfg Config) (*dirKeystore, error) {
	ks := &dirKeystore{
		cfg:  cfg,
		root: storage.OpenOS(cfg.Root),
	}

	err := ks.root.MkdirAll(cfg.PublicDir, 0700)
	if err != nil && !os.IsExist(err) {
		panic("unable to create public keysets directory: " + err.Error())
	}
	err = ks.root.MkdirAll(cfg.PrivateDir, 0700)
	if err != nil && !os.IsExist(err) {
		panic("unable to create private keysets directory: " + err.Error())
	}

	ks.pubs = ks.root.ChangeDir(cfg.PublicDir)
	ks.priv = ks.root.ChangeDir(cfg.PrivateDir)

	pubs, err := ks.loadEntries(false)
	if err != nil {
		return nil, err
	}
	ks.keys = make(map[string]bool, len(pubs))

	privs, err := ks.loadEntries(true)
	if err != nil {
		return nil, err
	}
	for _, id := range pubs {
		ks.keys[id] = false
	}
	for _, id := range privs {
		if _, ok := ks.keys[id]; !ok {
			// TODO: no public key
			continue
		}
		ks.keys[id] = true
	}
	return ks, nil
}

var _ keystore.Keystore = (*dirKeystore)(nil)

type dirKeystore struct {
	root, pubs, priv storage.FS

	cfg Config

	keys map[string]bool
}

var _ keystore.Key = key{}

type key struct {
	ks *dirKeystore

	id      string
	private bool
}

func (k key) ID() quark.ID {
	id, _ := quark.IDFromString(k.id)
	return id
}

func (k key) IsPrivateExists() bool { return k.private }

func (k key) Public() (quark.Public, error) {

}

func (k key) Private() (quark.Private, error) {

}

// Find finds public keyset by id, owner name or email.
// It return ErrNotFound if the keyset is not found.
func (ks *dirKeystore) Find(query keystore.Query) (keystore.Key, error) {
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

// Delete deletes a key by id.
// It return ErrNotFound if the keyset is not found.
func (ks *dirKeystore) Delete(id quark.ID) error {
	ks, err := Find(query)
	if err != nil {
		return "", err
	}

	id = ks.ID().String()

	if def, err := IsDefault(id); err != nil {
		return id, err
	} else if def {
		_, err = SetDefault("")
		if err != nil {
			return id, err
		}
	}
	err = storage.Private().Remove(PrivateFileName(id))
	if err != nil && !os.IsNotExist(err) {
		return id, err
	}

	return id, storage.Public().Remove(PublicFileName(id))
}

// Edit edits a keyset.
func Edit(query string, id quark.Identity) (quark.Public, error) {
	privName, err := findPrivate(query)
	if err != nil {
		return nil, err
	}

	passphrase, priv, err := readPrivWithPassphrase(privName)
	if err != nil {
		return nil, err
	}

	old := priv.Identity()
	if id.Name == "" {
		id.Name = old.Name
	}
	if id.Email == "" {
		id.Email = old.Email
	}
	if id.Comment == "" {
		id.Comment = old.Comment
	}

	pub := priv.Public()

	err = priv.ChangeIdentity(id)
	if err != nil {
		return pub, err
	}

	err = writePriv(false, priv, func() (string, error) { return passphrase, nil })
	if err != nil {
		return pub, err
	}
	err = writePub(false, pub)
	if err != nil {
		return pub, err
	}
	return pub, err
}

// ImportPublic imports a public keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func (ks *dirKeystore) ImportPublic(pub quark.Public) error {
	return writePub(true, pub)
}

// ImportPrivate imports a private keyset.
// It returns ErrAlreadyExists if the keyset already exists.
func (ks *dirKeystore) ImportPrivate(priv quark.Private) error {
	err := ImportPublic(priv.Public())
	if err != nil {
		return err
	}
	return writePriv(true, priv, PassphraseProvider)
}

// List lists all keysets.
func (ks *dirKeystore) List() ([]keystore.Key, error) {
	entries, err := listEntries(secrets)
	if err != nil {
		return nil, err
	}
	list := make([]quark.Public, 0, len(entries))
	for _, entry := range entries {
		pub, err := readPub(entry)
		if err != nil {
			return nil, err
		}
		list = append(list, pub)
	}
	return list, err
}
