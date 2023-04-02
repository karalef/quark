package keys

import (
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var ImportCMD = &cli.Command{
	Name:     "import",
	Usage:    "import a keyset",
	Category: "key management",
	Aliases:  []string{"imp"},
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return cli.NewExitError("must specify a keyset file to import", 1)
		}
		f, err := os.Open(c.Args().First())
		if err != nil {
			return err
		}
		defer f.Close()

		ks, err := pack.PreunpackPrivate(f)
		if err != nil {
			return err
		}

		// keyset is public
		if len(ks.SignPrivKey) == 0 {
			// verify public
			_, err := ks.PackedPublic.Load()
			if err != nil {
				return err
			}
			return writePubPrepacked(storage.PublicKeysFS(), ks.PackedPublic)
		}

		// verify private
		_, err = ks.Load()
		if err != nil {
			return err
		}

		err = writePubPrepacked(storage.PublicKeysFS(), ks.PackedPublic)
		if err != nil {
			return err
		}

		return writePrivPrepacked(storage.PrivateKeysFS(), ks)
	},
}

func ImportPublic(ks quark.PublicKeyset) error {
	return importPublic(ks)
}

func ImportPrivate(ks quark.PrivateKeyset) error {
	err := importPublic(ks)
	if err != nil {
		return err
	}
	return importPrivate(ks)
}

func importPublic(k quark.PublicKeyset) error {
	f, err := CreateFile(storage.PublicKeysFS(), pubFileName(quark.KeysetIDOf(k).String()))
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Public(f, k)
}

func importPrivate(k quark.PrivateKeyset) error {
	f, err := CreateFile(storage.PrivateKeysFS(), privFileName(quark.KeysetIDOf(k).String()))
	if err != nil {
		return err
	}
	defer f.Close()
	return pack.Private(f, k)
}
