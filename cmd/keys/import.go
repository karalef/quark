package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/urfave/cli/v2"
)

// ImportCMD is the command to import a keyset.
var ImportCMD = &cli.Command{
	Name:        "import",
	Usage:       "import an identity",
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

		v, err := input.Read()
		if err != nil {
			return err
		}

		ks := c.Context.Value(keystore.ContextKey).(keystore.Keystore)

		var fp quark.Fingerprint
		switch v.PacketTag() {
		case quark.PacketTagIdentity:
			ident := v.(quark.Identity)
			fp = ident.Fingerprint()
			err = importPub(ks, ident)
		case quark.PacketTagPrivateKey:
			priv := v.(quark.PrivateKey)
			fp = priv.Fingerprint()
			err = ks.ImportPrivate(priv)
		default:
			return cli.Exit("input does not contain a key", 1)
		}

		if err != nil {
			return err
		}

		cmdio.Status("imported", fp.String())
		return err
	},
}

func importPub(ks keystore.Keystore, identity quark.Identity) error {
	yes, err := cmdio.YesNo(identity.Fingerprint().String() + "\ndoes the key fingerprint match?")
	if err != nil {
		return err
	}
	if !yes {
		return cli.Exit("import cancelled", 1)
	}
	return ks.Import(identity, nil)
}
