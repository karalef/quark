package storage

import (
	"sync"

	"github.com/karalef/wfs"
)

const (
	pubkeysDir  = "pubkeys"
	privkeysDir = "privkeys"
)

var pubkeysOnce, privkeysOnce sync.Once

func PublicKeysFS() wfs.Filesystem {
	pubkeysOnce.Do(func() {
		rootFS.MkdirAll(pubkeysDir, 0600)
	})
	return rootFS.ChangeDir(pubkeysDir)
}

func PrivateKeysFS() wfs.Filesystem {
	privkeysOnce.Do(func() {
		rootFS.MkdirAll(privkeysDir, 0600)
	})
	return rootFS.ChangeDir(privkeysDir)
}
