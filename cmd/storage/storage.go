package storage

import (
	"os"
	"path/filepath"
)

const dirName = ".quark"

const (
	pubkeysDir  = "pubkeys"
	privkeysDir = "privkeys"
)

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

var rootFS = OpenOS(rootPath)

// RootFS returns the root filesystem.
func RootFS() FS { return rootFS }

var pubFS = func() FS {
	err := rootFS.MkdirAll(pubkeysDir, 0700)
	if err != nil && !os.IsExist(err) {
		panic("unable to create public keysets directory")
	}
	return rootFS.ChangeDir(pubkeysDir)
}()

// Public returns the public keysets filesystem.
func Public() FS { return pubFS }

var privFS = func() FS {
	err := rootFS.MkdirAll(privkeysDir, 0700)
	if err != nil && !os.IsExist(err) {
		panic("unable to create private keysets directory")
	}
	return rootFS.ChangeDir(privkeysDir)
}()

// Private returns the private keysets filesystem.
func Private() FS { return privFS }
