package keys

import (
	"sort"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
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

	ks, err := quark.Generate(identity, scheme)
	if err != nil {
		return err
	}

	err = keyring.ImportPrivate(ks)
	if err != nil {
		return err
	}

	if ok, err := keyring.IsDefaultExists(); err != nil {
		return cli.Exit("default keyset: "+err.Error(), 1)
	} else if !ok {
		err = keyring.SetDefaultByID(ks.ID().String())
		if err != nil {
			return err
		}
	}
	cmdio.Status("generated keyset", ks.ID())
	return nil
}

var defaultScheme = quark.Scheme{
	Sign: quark.Dilithium3ED448.Scheme(),
	KEM:  quark.Kyber768XChaCha20Poly1305.Scheme(),
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
	kems := quark.ListKEMAlgorithms()
	sort.Slice(kems, func(i, j int) bool {
		return kems[i] < kems[j]
	})
	for _, k := range kems {
		cmdio.Status(k)
	}

	cmdio.Status("\nSIGNATURES:")
	signs := quark.ListSignAlgorithms()
	sort.Slice(signs, func(i, j int) bool {
		return signs[i] < signs[j]
	})
	for _, s := range signs {
		cmdio.Status(s)
	}

	return nil
}
