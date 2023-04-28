package cmdio

import (
	"os"

	"github.com/urfave/cli/v2"
)

// FlagOutput is an output flag.
var FlagOutput = &cli.PathFlag{
	Name:      "output",
	Aliases:   []string{"o"},
	Usage:     "output `FILE` (override stdout)",
	TakesFile: true,
	Action: func(_ *cli.Context, path string) error {
		o, err := CustomRawOutput(path)
		if err != nil {
			return err
		}
		os.Stdout = o
		return nil
	},
}

// FlagArmor is an armor flag.
var FlagArmor = &cli.BoolFlag{
	Name:        "armor",
	Aliases:     []string{"a"},
	Usage:       "use ascii-armored output",
	Destination: &armor,
}

// FlagInput is an input flag.
var FlagInput = &cli.StringFlag{
	Name:      "input",
	Aliases:   []string{"i"},
	Usage:     "input `FILE` (override stdin)",
	TakesFile: true,
	Action: func(_ *cli.Context, path string) error {
		i, err := CustomInput(path)
		if err != nil {
			return err
		}
		os.Stdin = i
		return nil
	},
}
