package storage

import (
	"errors"
	"os"
	"path/filepath"
)

func Init(dir string) (FS, error) {
	p, err := os.UserHomeDir()
	if err != nil {
		return FS{}, errors.Join(err, errors.New("unable to get user home directory"))
	}
	full := filepath.Join(p, dir)
	err = os.MkdirAll(full, 0700)
	if err != nil && err != os.ErrExist {
		return FS{}, errors.Join(err, errors.New("unable to create storage directory"))
	}
	return OpenOS(full), nil
}
