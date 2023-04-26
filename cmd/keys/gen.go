package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/hash"
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
			Name:     "name",
			Usage:    "owner name",
			Aliases:  []string{"n"},
			Required: true,
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
	Hash: hash.SHA256.Scheme(),
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
	for _, k := range kem.ListAll() {
		cmdio.Status(k.Alg())
	}

	cmdio.Status("\nSIGNATURES:")
	for _, s := range sign.ListAll() {
		cmdio.Status(s.Alg())
	}

	cmdio.Status("\nHASHES:")
	for _, h := range hash.ListAll() {
		cmdio.Status(h.Alg())
	}

	return nil
}
