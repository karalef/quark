package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

// ListCMD is the command to list keysets.
var ListCMD = &cli.Command{
	Name:     "list",
	Aliases:  []string{"ls"},
	Usage:    "list keysets",
	Category: "key management",
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
			if i < len(pubs)-1 {
				cmdio.Status()
			}
		}
		return nil
	},
}

func printKeyset(info quark.KeysetInfo) {
	id := info.Identity
	cmdio.Statusf("%s\t%s <%s> (%s)\n%s\n%s\n", info.ID, id.Name, id.Email, id.Comment,
		info.Scheme.String(),
		info.Fingerprint.String())
}
