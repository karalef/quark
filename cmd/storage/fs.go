package storage

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OpenOS opens os directory as FS.
func OpenOS(root string) FS {
	return FS{root: root}
}

// FS provides an os directory as a filesystem.
type FS struct {
	root string
}

func (f FS) abs(name string) string {
	return filepath.Join(f.root, name)
}

// Symlink calls os.Symlink relatively FS`s root.
func (f FS) Symlink(oldname, newname string) error {
	return os.Symlink(f.abs(oldname), f.abs(newname))
}

// Readlink calls os.Readlink relatively FS`s root.
func (f FS) Readlink(name string) (string, error) {
	return os.Readlink(f.abs(name))
}

// OpenFile calls os.OpenFile relatively FS`s root.
func (f FS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(f.abs(name), flag, perm)
}

// ChangeDir creates a new FS with relative root.
func (f FS) ChangeDir(name string) FS { return FS{root: f.abs(name)} }

// Remove calls os.Remove relatively FS`s root.
func (f FS) Remove(name string) error { return os.Remove(f.abs(name)) }

// Mkdir calls os.Mkdir relatively FS`s root.
func (f FS) Mkdir(name string, perm fs.FileMode) error { return os.Mkdir(f.abs(name), perm) }

// Stat calls os.Stat relatively FS`s root.
func (f FS) Stat(name string) (os.FileInfo, error) { return os.Stat(f.abs(name)) }

// ReadDir calls os.ReadDir relatively FS`s root.
func (f FS) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(f.abs(name)) }

// Open calls os.Open relatively FS`s root.
func (f FS) Open(name string) (*os.File, error) { return os.Open(f.abs(name)) }

// Create calls os.Create relatively FS`s root.
func (f FS) Create(name string) (*os.File, error) { return os.Create(f.abs(name)) }

// MkdirAll calls os.MkdirAll relatively FS`s root.
func (f FS) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(f.abs(path), perm) }
