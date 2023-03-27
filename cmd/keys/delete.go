package keys

import (
	"errors"
	"os"

	"github.com/karalef/quark/cmd/storage"
	"github.com/urfave/cli/v2"
)

var DeleteCMD = &cli.Command{
	Name:     "delete",
	Usage:    "delete a keyset",
	Category: "key management",
	Aliases:  []string{"del"},
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return errors.New("must specify a keyset to delete")
		}
		keyID := c.Args().First()

		fs := storage.PublicKeysFS()
		ks, err := findKeysetFile(fs, keyID)
		if err != nil && err != os.ErrNotExist {
			return err
		}
		if ks != "" {
			goto delete
		}

		fs = storage.PrivateKeysFS()
		ks, err = findKeysetFile(fs, keyID)
		if err != nil {
			if err == os.ErrNotExist {
				return cli.NewExitError("keyset not found", 1)
			}
			return err
		}

	delete:
		return fs.Remove(ks)
	},
}
