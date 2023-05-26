package main

import (
	"os"

	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/enc"
	"github.com/karalef/quark/cmd/keys"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                   "quark",
		Version:                "0.1.1",
		Usage:                  "encrypt and sign messages",
		UseShortOptionHandling: true,
		Writer:                 os.Stderr,
		ErrWriter:              os.Stderr,
		DefaultCommand:         enc.DecryptCMD.Name,
		Commands: []*cli.Command{
			keys.GenerateCMD,
			keys.ListCMD,
			keys.ImportCMD,
			keys.ExportCMD,
			keys.DeleteCMD,
			keys.DefaultCMD,
			keys.EditCMD,
			enc.EncryptCMD,
			enc.DecryptCMD,
		},
	}

	if err := app.Run(os.Args); err != nil {
		cmdio.Status(err)
		os.Exit(1)
	}
}
