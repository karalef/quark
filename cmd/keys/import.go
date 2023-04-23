package keys

import (
	"fmt"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var ImportCMD = &cli.Command{
	Name:      "import",
	Usage:     "import a keyset",
	Category:  "key management",
	Aliases:   []string{"imp"},
	ArgsUsage: "<file>",
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return cli.Exit("must specify a keyset file to import", 1)
		}
		f, err := os.Open(c.Args().First())
		if err != nil {
			return err
		}
		defer f.Close()

		tag, v, err := pack.Decode(f)
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

		fmt.Println("imported", pub.ID())
		return err
	},
}
