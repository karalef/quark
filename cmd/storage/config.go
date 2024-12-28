package storage

import (
	"os"

	"github.com/karalef/quark-cmd/config"
)

func LoadConfig(fs FS, name string) (config.Config, error) {
	f, err := fs.Open(name)
	if err != nil {
		var cfg config.Config
		if os.IsNotExist(err) {
			err = nil
		}
		return cfg, err
	}
	defer f.Close()

	return config.Load(f)
}
