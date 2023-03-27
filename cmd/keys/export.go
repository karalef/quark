package keys

import (
	"os"

	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var ExportCMD = &cli.Command{
	Name:     "export",
	Usage:    "export a keyset",
	Category: "key management",
	Aliases:  []string{"exp"},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "f",
			Usage:    "export to file",
			Aliases:  []string{"file"},
			Required: true,
		},
	},
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return cli.ShowCommandHelp(c, "export")
		}

		fs := storage.PrivateKeysFS()
		pksFileName, err := findKeysetFile(fs, c.Args().First())
		if err != nil {
			return err
		}

		pksFile, err := fs.Open(pksFileName)
		if err != nil {
			return err
		}
		defer pksFile.Close()

		pks, err := pack.UnpackPrivate(pksFile)
		if err != nil {
			return err
		}

		f, err := os.OpenFile(c.String("f"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}

		return pack.Public(f, pks)
	},
}
