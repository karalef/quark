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

	var id string
	query := ctx.Args().First()
	if ctx.Bool("secret") {
		id, err = expKeyset(keyring.FindPrivate, query)
	} else {
		id, err = expKeyset(keyring.Find, query)
	}
	if err != nil {
		return err
	}

	cmdio.Status("exported", id)

	return nil
}

func expKeyset[T keyring.Keyset](find func(string) (T, error), query string) (string, error) {
	ks, err := find(query)
	if err != nil {
		return "", err
	}

	output, err := cmdio.Output(ks.PacketTag().BlockType())
	if err != nil {
		return ks.ID().String(), err
	}
	defer output.Close()

	return ks.ID().String(), pack.Pack(output, ks)
}
