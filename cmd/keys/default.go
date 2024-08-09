package keys

/*
import (
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/urfave/cli/v2"
)

// DefaultCMD is the command to print the default keyset.
var DefaultCMD = &cli.Command{
	Name:     "default",
	Usage:    "manage the default keyset",
	Category: "key management",
	Aliases:  []string{"def"},
	Action:   defaultKeyset,
	Subcommands: []*cli.Command{
		setDefaultCMD,
	},
}

func defaultKeyset(ctx *cli.Context) error {
	def, err := keystore.DefaultPublic()
	if err != nil {
		return err
	}
	printKeyset(def)
	return nil
}

var setDefaultCMD = &cli.Command{
	Name:      "set",
	Usage:     "set a default keyset (unset if no keyset is provided)",
	Category:  "key management",
	ArgsUsage: "[keyset]",
	Action:    setDefault,
}

func setDefault(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		_, err := keystore.SetDefault("")
		if err != nil {
			return err
		}
		cmdio.Status("default keyset unset")
		return nil
	}
	id, err := keystore.SetDefault(ctx.Args().First())
	if err != nil {
		return err
	}
	cmdio.Status("default keyset set:", id)
	return nil
}*/
