package dir

import (
	"os"
	"strings"

	"github.com/karalef/quark-cmd/storage"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/pack"
)

func fileName(id crypto.ID, ext string) string {
	return id.String() + "." + ext
}

func validateFileName(name string, ext string) (crypto.ID, bool) {
	if !strings.HasSuffix(name, ext) {
		return crypto.ID{}, false
	}
	return crypto.IDFromString(name[:len(name)-len(ext)-1])
}

func open(root storage.FS, name string, tag pack.Tag) (pack.Packable, error) {
	f, err := root.Open(name)
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
	if p.PacketTag() != tag {
		return nil, storage.ErrInvalidObject
	}

	return p, nil
}

func write(fs storage.FS, id crypto.ID, ext string, flag int, v pack.Packable) error {
	f, err := fs.OpenFile(fileName(id, ext), os.O_WRONLY|os.O_TRUNC|flag, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	err = pack.Pack(f, v)
	if err != nil {
		return err
	}
	return nil
}
