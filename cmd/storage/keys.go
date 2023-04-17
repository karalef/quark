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

var pubFS, privFS wfs.Filesystem

// PublicFS returns the public keysets filesystem.
func PublicFS() wfs.Filesystem {
	pubkeysOnce.Do(func() {
		rootFS.MkdirAll(pubkeysDir, 0700)
		pubFS = rootFS.ChangeDir(pubkeysDir)
	})
	return pubFS
}

// PrivateFS returns the private keysets filesystem.
func PrivateFS() wfs.Filesystem {
	privkeysOnce.Do(func() {
		rootFS.MkdirAll(privkeysDir, 0700)
		privFS = rootFS.ChangeDir(privkeysDir)
	})
	return privFS
}
