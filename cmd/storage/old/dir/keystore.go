package dir

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/storage"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/pack"
)

// NewPubring returns a new pubring.
func NewPubring(root storage.FS, ext string) storage.Pubring {
	return keystore[*quark.PublicKey[crypto.Key]]{
		root: root,
		ext:  ext,
		tag:  quark.PacketTagPublicKey,
	}
}

// NewSecrets returns a new secrets storage.
func NewSecrets(root storage.FS, ext string) storage.Secrets {
	return keystore[*quark.PrivateKey[crypto.Key]]{
		root: root,
		ext:  ext,
		tag:  quark.PacketTagPrivateKey,
	}
}

var (
	_ storage.Pubring = (*keystore[*quark.PublicKey[crypto.Key]])(nil)
	_ storage.Secrets = (*keystore[*quark.PrivateKey[crypto.Key]])(nil)
)

type keystore[T storage.Key] struct {
	root storage.FS
	ext  string
	tag  pack.Tag
}

func (s keystore[T]) ByID(id crypto.ID) (T, error) {
	p, err := open(s.root, fileName(id, s.ext), s.tag)
	if err != nil {
		return nil, err
	}
	return p.(T), nil
}

func (s keystore[_]) Count() (uint, error) {
	entries, err := s.root.ReadDir(".")
	if err != nil {
		return 0, err
	}

	var c uint
	for _, entry := range entries {
		if _, ok := validateFileName(entry.Name(), s.ext); ok && entry.Type().IsRegular() {
			c++
		}
	}
	return c, nil
}

func (s keystore[_]) Delete(id crypto.ID) error {
	err := s.root.Remove(fileName(id, s.ext))
	if os.IsNotExist(err) {
		return storage.ErrNotFound
	}
	return err
}

func (s keystore[_]) IsExists(id crypto.ID) (bool, error) {
	f, err := s.root.Open(fileName(id, s.ext))
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	f.Close()
	return true, nil
}

func (s keystore[T]) Store(key T) error {
	err := write(s.root, key.ID(), s.ext, os.O_CREATE|os.O_EXCL, key)
	if os.IsExist(err) {
		return storage.ErrExists
	}
	return err
}

func (s keystore[T]) Update(key T) error {
	err := write(s.root, key.ID(), s.ext, 0, key)
	if os.IsNotExist(err) {
		return storage.ErrNotFound
	}
	return err
}

func (s keystore[T]) VisitAll(f func(T) (stop bool, err error)) error {
	if f == nil {
		return nil
	}

	entries, err := s.root.ReadDir(".")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if _, ok := validateFileName(entry.Name(), s.ext); !ok {
			continue
		}

		p, err := open(s.root, entry.Name(), s.tag)
		if err != nil {
			if err == storage.ErrInvalidObject {
				continue
			}
			return err
		}

		stop, err := f(p.(T))
		if err != nil {
			return err
		}
		if stop {
			break
		}
	}
	return nil
}
