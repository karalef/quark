package main

import (
	"os"

	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/enc"
	"github.com/karalef/quark/cmd/keys"
	"github.com/urfave/cli/v2"
)

var flagOut = &cli.PathFlag{
	Name:      "output",
	Usage:     "output `FILE` (override stdout)",
	Aliases:   []string{"o"},
	TakesFile: true,
	Action: func(_ *cli.Context, v string) error {
		return cmdio.SetOutput(v)
	},
}

var flagArmor = &cli.BoolFlag{
	Name:        "armor",
	Aliases:     []string{"a"},
	Usage:       "use ascii-armored output",
	Destination: &cmdio.Armor,
}

var flagIn = &cli.StringFlag{
	Name:      "input",
	Usage:     "input `FILE` (override stdin)",
	Aliases:   []string{"i"},
	TakesFile: true,
	Action: func(_ *cli.Context, v string) error {
		return cmdio.SetInput(v)
	},
}

func main() {
	app := &cli.App{
		Name:                   "quark",
		Version:                "0.1 working alpha",
		Usage:                  "encrypt and sign messages",
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			flagArmor,
			flagOut,
			flagIn,
		},
		Writer:    os.Stderr,
		ErrWriter: os.Stderr,
		Commands: []*cli.Command{
			keys.GenerateCMD,
			keys.ListCMD,
			keys.ImportCMD,
			keys.ExportCMD,
			keys.DeleteCMD,
			keys.DefaultCMD,
			enc.EncryptCMD,
			enc.DecryptCMD,
		},
	}

	if err := app.Run(os.Args); err != nil {
		cmdio.Status(err)
		os.Exit(1)
	}
}
