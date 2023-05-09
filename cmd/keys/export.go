package keys

import (
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

// ExportCMD is the command to export a public keyset to a file.
var ExportCMD = &cli.Command{
	Name:      "export",
	Usage:     "export a public keyset to a file",
	Category:  "key management",
	Aliases:   []string{"exp"},
	ArgsUsage: "<keyset> [output file]",
	Flags: append(cmdio.OutputFlags(),
		&cli.BoolFlag{
			Name:    "secret",
			Usage:   "export private keyset",
			Aliases: []string{"s"},
		},
	),
	Action: export,
}

func export(ctx *cli.Context) (err error) {
	if !ctx.Args().Present() {
		return cli.ShowCommandHelp(ctx, "export")
	}

	output := cmdio.GetOutput()
	if out := ctx.Args().Get(1); out != "" {
		output, err = cmdio.CustomOutput(out)
		if err != nil {
			return
		}
	}

	query := ctx.Args().First()
	if ctx.Bool("secret") {
		return expSecret(output, query)
	}

	ks, err := keyring.Find(query)
	if err != nil {
		return err
	}
	return output.Write(ks)
}

func expSecret(output cmdio.Output, query string) error {
	ks, err := keyring.FindPrivate(query)
	if err != nil {
		return err
	}
	cmdio.Status("private key backup requires a passphrase")
	err = cmdio.WithPassphrase("keyset backup passphrase")
	if err != nil {
		return err
	}
	return output.Write(ks)
}
