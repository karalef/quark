package fs

import (
	"fmt"
	"os"
	"strings"

	"github.com/karalef/quark-cmd/storage"
	"github.com/karalef/quark/pack"
)

// New returns a new filesystem storage.
func New[ID fmt.Stringer, T storage.Object[ID]](root storage.FS, ext string, v ValidateID) store[ID, T] {
	var empty T
	return store[ID, T]{
		root: root,
		ext:  ext,
		tag:  empty.PacketTag(),
		val:  v,
	}
}

// ValidateID returns true if the ID is valid.
type ValidateID func(string) bool

var _ storage.Storage[fmt.Stringer, storage.Object[fmt.Stringer]] = store[fmt.Stringer, storage.Object[fmt.Stringer]]{}

type store[ID fmt.Stringer, T storage.Object[ID]] struct {
	val  ValidateID
	root storage.FS
	ext  string
	tag  pack.Tag
}

func (s store[ID, T]) ByID(id ID) (T, error) {
	p, err := s.open(s.fileName(id))
	if err != nil {
		var empty T
		return empty, err
	}
	return p.(T), nil
}

func (s store[_, _]) Count() (uint, error) {
	entries, err := s.root.ReadDir(".")
	if err != nil {
		return 0, err
	}

	var c uint
	for _, entry := range entries {
		if entry.Type().IsRegular() && s.validateName(entry.Name()) {
			c++
		}
	}
	return c, nil
}

func (s store[ID, _]) Delete(id ID) error {
	err := s.root.Remove(s.fileName(id))
	if os.IsNotExist(err) {
		return storage.ErrNotFound
	}
	return err
}

func (s store[ID, _]) IsExists(id ID) (bool, error) {
	f, err := s.root.Open(s.fileName(id))
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	f.Close()
	return true, nil
}

func (s store[_, T]) Store(obj T) error {
	err := s.write(obj, os.O_CREATE|os.O_EXCL)
	if os.IsExist(err) {
		return storage.ErrExists
	}
	return err
}

func (s store[_, T]) Update(obj T) error {
	err := s.write(obj, 0)
	if os.IsNotExist(err) {
		return storage.ErrNotFound
	}
	return err
}

func (s store[_, T]) VisitAll(f func(T) (stop bool, err error)) error {
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
		if !s.validateName(entry.Name()) {
			continue
		}

		p, err := s.open(entry.Name())
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

func (s store[ID, _]) fileName(id ID) string {
	return id.String() + "." + s.ext
}

func (s store[ID, _]) validateName(name string) bool {
	if !strings.HasSuffix(name, s.ext) {
		return false
	}
	if s.val == nil {
		return true
	}
	return s.val(name[:len(name)-len(s.ext)-1])
}

func (s store[_, T]) write(obj T, flag int) error {
	f, err := s.root.OpenFile(s.fileName(obj.ID()), os.O_WRONLY|os.O_TRUNC|flag, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	err = pack.Pack(f, obj)
	if err != nil {
		return err
	}
	return nil
}

func (s store[_, _]) open(name string) (pack.Packable, error) {
	f, err := s.root.Open(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	defer f.Close()

	p, err := pack.Unpack(f)
	if err != nil {
		return nil, err
	}
	if p.PacketTag() != s.tag {
		return nil, storage.ErrInvalidObject
	}

	return p, nil
}
