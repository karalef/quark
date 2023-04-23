package keys

import (
	"fmt"
	"os"

	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

// ExportCMD is the command to export a public keyset to a file.
var ExportCMD = &cli.Command{
	Name:      "export",
	Usage:     "export a public keyset to a file",
	Category:  "key management",
	Aliases:   []string{"exp"},
	ArgsUsage: "<keyset>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "f",
			Usage:   "file name",
			Aliases: []string{"file"},
		},
	},
	Action: export,
}

func export(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		return cli.ShowCommandHelp(ctx, "export")
	}

	pks, err := keyring.Find(ctx.Args().First())
	if err != nil {
		return err
	}

	file := ctx.String("f")
	if file == "" {
		file = keyring.PublicFileName(pks.Identity().Name)
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

	fmt.Println("exported", pks.ID(), file)

	return nil
}
