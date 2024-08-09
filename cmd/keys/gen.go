package keys

import (
	"sort"

	"github.com/karalef/quark"
	"github.com/karalef/quark/bind"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/crypto/sign"
	"github.com/urfave/cli/v2"
)

// GenerateCMD is the command to generate a new identity.
var GenerateCMD = &cli.Command{
	Name:      "generate",
	Usage:     "generate a new identity",
	Category:  "key management",
	Aliases:   []string{"gen"},
	ArgsUsage: "{algorithm}",
	Subcommands: []*cli.Command{
		listCMD,
	},
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
	},
	Action: generate,
}

func generate(ctx *cli.Context) error {
	scheme := defaultScheme
	if strScheme := ctx.Args().First(); strScheme != "" {
		sch := sign.ByName(strScheme)
		if sch == nil {
			return printSchemes(ctx)
		}
		scheme = sch
	}

	identity, sk, err := quark.Generate(scheme, 0)
	if err != nil {
		return err
	}
	if name := ctx.String("name"); name != "" {
		_, err := bind.Ident(identity, sk, bind.TypeName, "", name, 0)
		if err != nil {
			return err
		}
	}
	if email := ctx.String("email"); email != "" {
		_, err := bind.Ident(identity, sk, bind.TypeEmail, "", email, 0)
		if err != nil {
			return err
		}
	}

	ks := ctx.Context.Value(keystore.ContextKey).(keystore.Keystore)

	err = ks.Import(identity, sk)
	if err != nil {
		return err
	}

	cmdio.Status("generated identity", identity.ID())
	return nil
}

var defaultScheme = sign.Scheme(sign.EDDilithium3)

var listCMD = &cli.Command{
	Name:    "list",
	Usage:   "list all available schemes",
	Aliases: []string{"l"},
	Action:  printSchemes,
}

func printSchemes(*cli.Context) error {
	cmdio.Status("All available algorithms")
	signs := sign.ListAll()
	sort.Slice(signs, func(i, j int) bool {
		return signs[i] < signs[j]
	})
	for _, s := range signs {
		cmdio.Status(s)
	}

	return nil
}
