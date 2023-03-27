package main

import (
	"os"

	"github.com/karalef/quark/cmd/enc"
	"github.com/karalef/quark/cmd/keys"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                   "quark",
		Version:                "0.0.1-first-half-working-build",
		Usage:                  "encrypt and sign messages",
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			keys.Gen,
			keys.ListCMD,
			keys.ImportCMD,
			keys.ExportCMD,
			keys.DeleteCMD,
			enc.EncryptCMD,
			enc.DecryptCMD,
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
