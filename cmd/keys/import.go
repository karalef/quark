package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
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
		input := cmdio.GetInput()
		if c.Args().Present() { // override stdin
			input, err = cmdio.CustomInput(c.Args().First())
			if err != nil {
				return err
			}
		}

		tag, v, err := input.Read()
		if err != nil {
			return err
		}

		var pub quark.Public
		switch tag {
		case quark.PacketTagPublicKeyset:
			pub = v.(quark.Public)
			err = importPub(pub)
		case quark.PacketTagPrivateKeyset:
			priv := v.(quark.Private)
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

func importPub(pub quark.Public) error {
	yes, err := cmdio.YesNo(pub.Fingerprint().String() + "\ndoes the keyset fingerprint match?")
	if err != nil {
		return err
	}
	if !yes {
		return cli.Exit("import cancelled", 1)
	}
	return keyring.ImportPublic(pub)
}
