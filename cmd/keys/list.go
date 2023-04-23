package keys

import (
	"fmt"

	"github.com/karalef/quark/cmd/keyring"
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
		pubs, err := keyring.List(c.Bool("s"))
		if err != nil {
			return err
		}
		for i := range pubs {
			printKeyset(pubs[i])
		}
		return nil
	},
}

func printKeyset(k keyring.KeysetEntry) {
	id := k.Identity
	fmt.Printf("%s\t%s <%s>\n\t%s\t%s\n", k.ID, id.Name, id.Email, k.Scheme.String(), k.FP.String())
}
