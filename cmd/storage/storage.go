package storage

import (
	"os"
	"path/filepath"
)

const dirName = ".quark"

var rootPath = func() string {
	p, err := os.UserHomeDir()
	if err != nil {
		panic("unable to get user home directory")
	}
	err = os.MkdirAll(filepath.Join(p, dirName), 0700)
	if err != nil && err != os.ErrExist {
		panic("unable to create storage directory")
	}
	return filepath.Join(p, dirName)
}()
