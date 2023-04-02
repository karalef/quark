package keys

import (
	"fmt"
	"os"

	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var ExportCMD = &cli.Command{
	Name:      "export",
	Usage:     "export a public keyset to a file",
	Category:  "key management",
	Aliases:   []string{"exp"},
	ArgsUsage: "<id>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "f",
			Usage:   "file name",
			Aliases: []string{"file"},
		},
	},
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return cli.ShowCommandHelp(c, "export")
		}

		pks, err := UsePublic(c.Args().First())
		if err != nil {
			return err
		}

		file := c.String("f")
		if file == "" {
			file = pubFileName(pks.Identity().Name)
		}

		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()

		err = pack.Public(f, pks)
		if err != nil {
			return err
		}

		fmt.Println("exported", IDOf(pks), file)

		return nil
	},
}
