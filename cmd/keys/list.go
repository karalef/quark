package keys

import (
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
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
		ks := c.Context.Value(keystore.ContextKey).(keystore.Keystore)
		keys, err := ks.List("")
		if err != nil {
			return err
		}
		secrets := c.Bool("s")
		for i := range keys {
			if !secrets || keys[i].IsPrivateExists() {
				printKey(keys[i])
			}
			if i < len(keys)-1 {
				cmdio.Status()
			}
		}
		return nil
	},
}

func printKey(key keystore.Key) {
	id := key.Identity()
	cmdio.Statusf("%s\t%s <%s> (%s)\n%s\n%s\n", key.ID().String(), id.Name, id.Email, id.Comment,
		key.Scheme().String(),
		key.Fingerprint().String())
}
