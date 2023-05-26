package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

// EditCMD is the command to edit a keyset.
var EditCMD = &cli.Command{
	Name:      "edit",
	Usage:     "edit a keyset",
	Category:  "key management",
	ArgsUsage: "<keyset>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "name",
			Usage:   "owner name",
			Aliases: []string{"n"},
		},
		&cli.StringFlag{
			Name:    "email",
			Usage:   "owner email",
			Aliases: []string{"e"},
		},
		&cli.StringFlag{
			Name:    "comment",
			Usage:   "comment",
			Aliases: []string{"c"},
		},
	},
	Action: edit,
}

func edit(ctx *cli.Context) error {
	if !ctx.Args().Present() {
		return cli.Exit("must specify a keyset to edit", 1)
	}
	query := ctx.Args().First()

	pub, err := keyring.Edit(query, quark.Identity{
		Name:    ctx.String("name"),
		Email:   ctx.String("email"),
		Comment: ctx.String("comment"),
	})
	if err != nil {
		return err
	}

	printKeyset(keyring.KeysetEntry{
		ID:       pub.ID().String(),
		FP:       pub.Fingerprint(),
		Identity: pub.Identity(),
		Scheme:   pub.Scheme(),
	})
	return nil
}
