package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

// ImportCMD is the command to import a keyset.
var ImportCMD = &cli.Command{
	Name:        "import",
	Usage:       "import a keyset",
	Category:    "key management",
	Aliases:     []string{"imp"},
	ArgsUsage:   "[file]",
	Description: "If the file is passed as argument it overrides the default input",
	Action: func(c *cli.Context) (err error) {
		input := cmdio.Input()
		if !c.Args().Present() { // override stdin
			input, err = cmdio.CustomInput(c.Args().First())
			if err != nil {
				return err
			}
			defer input.Close()
		}

		tag, v, err := pack.Decode(input)
		if err != nil {
			return err
		}

		var pub *quark.Public
		switch tag {
		case pack.TagPublicKeyset:
			pub = v.(*quark.Public)
			err = keyring.ImportPublic(pub)
		case pack.TagPrivateKeyset:
			priv := v.(*quark.Private)
			pub = priv.Public()
			err = keyring.ImportPrivate(priv)
		default:
			return cli.Exit("input does not contain a keyset", 1)
		}

		if err != nil {
			return err
		}

		cmdio.Status("imported", pub.ID())
		return err
	},
}
