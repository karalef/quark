package keys

import (
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
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
	priv, err := keyring.Default()
	if err != nil {
		return err
	}
	printKeyset(keyring.KeysetEntry{
		ID:       priv.ID().String(),
		FP:       priv.Fingerprint(),
		Identity: priv.Identity(),
		Scheme:   priv.Scheme(),
	})
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
		err := keyring.SetDefault("")
		if err != nil {
			return err
		}
		cmdio.Status("default keyset unset")
		return nil
	}
	priv, err := keyring.FindPrivate(ctx.Args().First())
	if err != nil {
		return err
	}
	err = keyring.SetDefault(priv.ID().String())
	if err != nil {
		return err
	}
	cmdio.Status("default keyset set:", priv.ID().String())
	return nil
}
