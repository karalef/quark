package keys

import (
	"os"

	"github.com/karalef/quark/cmd/storage"
	"github.com/urfave/cli/v2"
)

var ImportCMD = &cli.Command{
	Name:     "import",
	Usage:    "import a keyset",
	Category: "key management",
	Aliases:  []string{"imp"},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "f",
			Usage:    "keyset file",
			Aliases:  []string{"file"},
			Required: true,
		},
	},
	Action: func(c *cli.Context) error {
		f, err := os.Open(c.String("f"))
		if err != nil {
			return err
		}
		defer f.Close()

		ks, err := loadKeyset(f)
		if err != nil {
			return err
		}

		if ks.IsPrivate {
			priv, err := ks.UnpackPrivate()
			if err != nil {
				return err
			}
			return WritePrivFile(storage.PrivateKeysFS(), priv)
		}

		pub, err := ks.UnpackPublic()
		if err != nil {
			return err
		}
		return WritePubFile(storage.PublicKeysFS(), pub)
	},
}
