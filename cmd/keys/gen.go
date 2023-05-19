package keys

import (
	"sort"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
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
		Name:  ctx.String("n"),
		Email: ctx.String("e"),
	}

	if identity.Name == "" {
		return cli.Exit("keyset cannot be created without owner name", 1)
	}

	ks, err := quark.Generate(identity, scheme)
	if err != nil {
		return err
	}

	err = keyring.ImportPrivate(ks)
	if err != nil {
		return err
	}
	cmdio.Status("generated keyset", ks.ID())
	return nil
}

var defaultScheme = quark.Scheme{
	KEM:  kem.Kyber768XChaCha20Poly1305.Scheme(),
	Sign: sign.Dilithium3ED448.Scheme(),
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
		return kems[i].Alg() < kems[j].Alg()
	})
	for _, k := range kems {
		cmdio.Status(k.Alg())
	}

	cmdio.Status("\nSIGNATURES:")
	signs := sign.ListAll()
	sort.Slice(signs, func(i, j int) bool {
		return signs[i].Alg() < signs[j].Alg()
	})
	for _, s := range signs {
		cmdio.Status(s.Alg())
	}

	return nil
}
