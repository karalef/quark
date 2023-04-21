package keys

import (
	"errors"
	"fmt"

	"github.com/karalef/quark"
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
			printKeyset(pubs[i])
		}
		return nil
	},
}

type keysetData struct {
	fp       quark.Fingerprint
	identity quark.Identity
	scheme   quark.Scheme
}

func list(secrets bool) ([]keysetData, error) {
	fs := storage.PublicFS()
	if secrets {
		fs = storage.PrivateFS()
	}
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]keysetData, 0, len(dir))
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		f, err := fs.Open(entry.Name())
		if err != nil {
			return nil, err
		}

		tag, v, err := pack.Unpack(f)
		f.Close()
		if err != nil {
			return nil, err
		}

		var pub *quark.Public
		switch tag {
		case pack.TagPublicKeyset:
			pub = v.(*quark.Public)
		case pack.TagPrivateKeyset:
			pub = v.(*quark.Private).Public()
		default:
			return nil, errors.New(f.Name() + " does not contain a keyset")
		}

		list = append(list, keysetData{
			fp:       pub.Fingerprint(),
			identity: pub.Identity(),
			scheme:   pub.Scheme(),
		})
	}
	return list, err
}

func printKeyset(k keysetData) {
	id := k.identity
	fmt.Printf("%s\t%s <%s>\n\t%s\t%s\n", IDByFP(k.fp), id.Name, id.Email, k.scheme.String(), k.fp.String())
}
