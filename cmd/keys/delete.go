package keys

import (
	"fmt"

	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

// DeleteCMD is the command to delete a keyset.
var DeleteCMD = &cli.Command{
	Name:      "delete",
	Usage:     "delete a keyset",
	Category:  "key management",
	Aliases:   []string{"del"},
	ArgsUsage: "<id>",
	Action:    delete,
}

func delete(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		return cli.Exit("must specify a keyset to delete", 1)
	}
	keyID := ctx.Args().First()

	_, err := keyring.DeleteByID(keyID)
	if err != nil {
		return err
	}

	fmt.Println("deleted", keyID)
	return nil
}
