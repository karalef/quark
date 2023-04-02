package keys

import (
	"fmt"

	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var ListCMD = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "list keysets",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "s",
			Aliases: []string{"secrets"},
			Usage:   "list secret keysets",
		},
	},
	Action: func(c *cli.Context) error {
		pubs, err := list(c.Bool("s"))
		if err != nil {
			return err
		}
		for i := range pubs {
			printKey(pubs[i])
		}
		return nil
	},
}

func list(secrets bool) ([]pack.KeysetData, error) {
	fs := storage.PublicKeysFS()
	if secrets {
		fs = storage.PrivateKeysFS()
	}
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]pack.KeysetData, 0, len(dir))
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		f, err := fs.Open(entry.Name())
		if err != nil {
			return nil, err
		}
		var ksd pack.KeysetData
		if secrets {
			pk, err := pack.PreunpackPrivate(f)
			if err != nil {
				return nil, err
			}
			ksd = pk.KeysetData
		} else {
			pk, err := pack.PreunpackPublic(f)
			if err != nil {
				return nil, err
			}
			ksd = pk.KeysetData

		}

		list = append(list, ksd)
	}
	return list, err
}

func printKey(k pack.KeysetData) {
	fmt.Printf("%s\t%s <%s>\n\t%s\t%s\n", IDByFP(k.Fingerprint), k.Identity.Name, k.Identity.Email, k.Scheme, k.Fingerprint.String())
}
