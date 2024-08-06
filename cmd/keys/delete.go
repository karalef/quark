package keys

import (
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/urfave/cli/v2"
)

// DeleteCMD is the command to delete a keyset.
var DeleteCMD = &cli.Command{
	Name:      "delete",
	Usage:     "delete a keyset",
	Category:  "key management",
	Aliases:   []string{"del"},
	ArgsUsage: "<keyset>",
	Action:    delete,
}

func delete(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		return cli.Exit("must specify a keyset to delete", 1)
	}
	query := ctx.Args().First()

	ks := ctx.Context.Value(keystore.ContextKey).(keystore.Keystore)
	id, err := keystore.DeleteByString(ks, query)
	if err != nil {
		return err
	}

	cmdio.Status("deleted", id)
	return nil
}
