package cmdio

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

// OutputFlags returns the output flags.
func OutputFlags() []cli.Flag {
	return []cli.Flag{
		FlagOutput,
		FlagArmor,
		FlagCompression,
	}
}

// InputFlags returns the input flags.
func InputFlags() []cli.Flag {
	return []cli.Flag{
		FlagInput,
	}
}

// IOFlags returns both input and output flags.
func IOFlags() []cli.Flag {
	return append(InputFlags(), OutputFlags()...)
}

// CustomIO accept input and output arguments and returns custom input and output.
func CustomIO(inputArg, outputArg string, outputName func(string) string) (input Input, output Output, err error) {
	input, output = GetInput(), GetOutput()
	if inputArg == "" {
		return
	}
	if inputArg != "-" { // override input
		input, err = CustomInput(inputArg)
		if err != nil {
			return
		}
	}

	if outputArg == "" {
		outputArg = outputName(inputArg)
	}
	if outputArg != "-" { // override output
		output, err = CustomOutput(outputArg)
	}
	return
}

// FlagOutput is an output flag.
var FlagOutput = &cli.PathFlag{
	Name:      "output",
	Aliases:   []string{"o"},
	Usage:     "output `FILE` (override stdout)",
	TakesFile: true,
	Action: func(_ *cli.Context, path string) error {
		o, err := CustomOutput(path)
		if err != nil {
			return err
		}
		os.Stdout = o.Raw()
		return nil
	},
}

// FlagArmor is an armor flag.
var FlagArmor = &cli.BoolFlag{
	Name:        "armor",
	Aliases:     []string{"a"},
	Usage:       "use ascii-armored output",
	Destination: &armor,
	DefaultText: "enabled by default for terminal output",
}

var str2compression = map[string]func(int) pack.Compressor{
	"deflate": pack.Deflate,
	"zstd":    pack.Zstd,
	"lz4":     func(lvl int) pack.Compressor { return pack.Lz4(lvl) },
}

// FlagCompression is a compression flag.
var FlagCompression = &cli.StringFlag{
	Name:        "compression",
	Usage:       "compression `ALGORITHM:LVL`",
	DefaultText: "no compression",
	Action: func(_ *cli.Context, v string) error {
		i := strings.Index(v, ":")
		if i == 0 {
			return cli.Exit(fmt.Errorf("invalid compression: %s", v), 1)
		}
		var alg string
		var lvl int
		if i == -1 {
			alg = v
		} else {
			alg = v[:i]
			lvl, _ = strconv.Atoi(v[i+1:])
		}
		c, ok := str2compression[alg]
		if ok {
			compressor = c(lvl)
			return nil
		}
		list := make([]string, 0, len(str2compression))
		for k := range str2compression {
			list = append(list, k)
		}
		return cli.Exit(fmt.Errorf("available compression algorithms: %s", strings.Join(list, ", ")), 1)
	},
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
		os.Stdin = i.Raw()
		return nil
	},
}
