package keys

import (
	"github.com/karalef/quark/cmd/cmdio"
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
		cmdio.FlagArmor,
		cmdio.FlagOutput,
		cmdio.FlagInput,
		&cli.BoolFlag{
			Name:    "secret",
			Usage:   "export private keyset",
			Aliases: []string{"s"},
		},
	},
	Action: export,
}

func export(ctx *cli.Context) (err error) {
	if !ctx.Args().Present() {
		return cli.ShowCommandHelp(ctx, "export")
	}

	query := ctx.Args().First()
	if ctx.Bool("secret") {
		err = expKeyset(keyring.FindPrivate, pack.Private, pack.BlockTypePrivate, query)
	} else {
		err = expKeyset(keyring.Find, pack.Public, pack.BlockTypePublic, query)
	}
	if err != nil {
		return err
	}

	return nil
}

func expKeyset[T keyring.Keyset](find func(string) (T, error), packer pack.Packer[T], blockType, query string) error {
	ks, err := find(query)
	if err != nil {
		return err
	}

	output, err := cmdio.Output(blockType)
	if err != nil {
		return err
	}
	defer output.Close()

	return packer(output, ks)
}
