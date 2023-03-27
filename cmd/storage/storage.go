package storage

import (
	"os"
	"path/filepath"

	"github.com/karalef/wfs"
)

const dirName = ".quark"

var rootPath = func() string {
	p, err := os.UserHomeDir()
	if err != nil {
		panic("unable to get user home directory")
	}
	os.MkdirAll(filepath.Join(p, dirName), 0755)
	return filepath.Join(p, dirName)
}()

var rootFS = wfs.OpenOS(rootPath)
