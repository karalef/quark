package keys

import (
	"errors"
	"fmt"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
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
			return cli.NewExitError("must specify a keyset file to import", 1)
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
			err = ImportPublic(pub)
		case pack.TagPrivateKeyset:
			priv := v.(*quark.Private)
			pub = priv.Public()
			err = ImportPrivate(priv)
		default:
			return errors.New("input does not contain a keyset")
		}

		if err != nil {
			return err
		}

		fmt.Println("imported", pub.ID())
		return err
	},
}

func ImportPublic(k *quark.Public) error {
	return writePub(storage.PublicFS(), k, "")
}

func ImportPrivate(ks *quark.Private) error {
	err := ImportPublic(ks.Public())
	if err != nil {
		return err
	}
	return writePriv(storage.PrivateFS(), ks, "")
}
