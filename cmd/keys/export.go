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
	Action:    export,
}

func export(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		return cli.ShowCommandHelp(ctx, "export")
	}

	pks, err := keyring.Find(ctx.Args().First())
	if err != nil {
		return err
	}

	output, err := cmdio.Output(pack.BlockTypePublic)
	if err != nil {
		return err
	}
	defer output.Close()

	err = pack.Public(output, pks)
	if err != nil {
		return err
	}

	cmdio.Status("exported", pks.ID())

	return nil
}
