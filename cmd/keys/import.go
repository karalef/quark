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
			ident := v.(*quark.Identity)
			fp, err = importIdentity(ks, ident)
		case quark.PacketTagPrivateKey:
			priv := v.(*quark.EncryptedKey)
			fp, err = importPrivate(ks, priv)
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

func importIdentity(ks keystore.Keystore, identity *quark.Identity) (fp quark.Fingerprint, err error) {
	yes, err := cmdio.YesNo(identity.Fingerprint().String() + "\ndoes the key fingerprint match?")
	if err != nil {
		return fp, err
	}
	if !yes {
		return fp, cli.Exit("import cancelled", 1)
	}
	return identity.Fingerprint(), ks.Import(identity)
}

func importPrivate(ks keystore.Keystore, esk *quark.EncryptedKey) (quark.Fingerprint, error) {
	panic("unimplemented")
}
