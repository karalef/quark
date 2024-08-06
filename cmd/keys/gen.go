package keys

import (
	"sort"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/urfave/cli/v2"
)

// GenerateCMD is the command to generate a new keyset.
var GenerateCMD = &cli.Command{
	Name:      "generate",
	Usage:     "generate a new keyset",
	Category:  "key management",
	Aliases:   []string{"gen"},
	ArgsUsage: "<scheme>",
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
		&cli.StringFlag{
			Name:    "comment",
			Usage:   "comment",
			Aliases: []string{"c"},
		},
	},
	Action: generate,
}

func generate(ctx *cli.Context) error {
	scheme := defaultScheme
	if strScheme := ctx.Args().First(); strScheme != "" {
		sch, err := quark.ParseScheme(strScheme)
		if err != nil {
			return err
		}
		scheme = sch
	}

	identity := quark.Identity{
		Name:    ctx.String("name"),
		Email:   ctx.String("email"),
		Comment: ctx.String("comment"),
	}

	if identity.Name == "" {
		return cli.Exit("keyset cannot be created without owner name", 1)
	}

	key, err := quark.Generate(identity, scheme, 0)
	if err != nil {
		return err
	}

	ks := ctx.Context.Value(keystore.ContextKey).(keystore.Keystore)

	err = ks.ImportPrivate(key)
	if err != nil {
		return err
	}

	// TODO: set default

	cmdio.Status("generated key", key.ID())
	return nil
}

var defaultScheme = quark.Scheme{
	Cert: sign.Dilithium3,
	Sign: sign.Dilithium3,
	KEM:  kem.Kyber768,
}

var listCMD = &cli.Command{
	Name:    "list",
	Usage:   "list all available schemes",
	Aliases: []string{"l"},
	Action:  printSchemes,
}

func printSchemes(*cli.Context) error {
	cmdio.Status("All available algorithms")

	cmdio.Status("\nKEM:")
	kems := kem.ListAll()
	sort.Slice(kems, func(i, j int) bool {
		return kems[i] < kems[j]
	})
	for _, k := range kems {
		cmdio.Status(k)
	}

	cmdio.Status("\nSIGNATURES:")
	signs := sign.ListAll()
	sort.Slice(signs, func(i, j int) bool {
		return signs[i] < signs[j]
	})
	for _, s := range signs {
		cmdio.Status(s)
	}

	return nil
}
