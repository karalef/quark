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
		return expKeyset(keyring.FindPrivate, query)
	}
	return expKeyset(keyring.Find, query)
}

func expKeyset[T keyring.Keyset](find func(string) (T, error), query string) error {
	ks, err := find(query)
	if err != nil {
		return err
	}

	output, err := cmdio.Output(ks.PacketTag().BlockType())
	if err != nil {
		return err
	}
	defer output.Close()

	return pack.Pack(output, ks)
}
