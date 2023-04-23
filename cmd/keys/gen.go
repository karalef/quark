package keys

import (
	"fmt"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
	"github.com/urfave/cli/v2"
)

// GenerateCMD is the command to generate a new keyset.
var GenerateCMD = &cli.Command{
	Name:      "gen",
	Usage:     "generate a new keyset",
	Category:  "key management",
	Aliases:   []string{"generate"},
	ArgsUsage: "<scheme>",
	Subcommands: []*cli.Command{
		listCMD,
	},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "n",
			Usage:   "owner name",
			Aliases: []string{"name"},
		},
		&cli.StringFlag{
			Name:    "e",
			Usage:   "owner email",
			Aliases: []string{"email"},
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
	fmt.Println("generated keyset", ks.ID())
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
	Aliases: []string{"l", "list-schemes"},
	Action:  printSchemes,
}

func printSchemes(*cli.Context) error {
	fmt.Println("All available algorithms")

	fmt.Println("\nKEM:")
	for _, k := range kem.ListAll() {
		fmt.Println(k.Alg())
	}

	fmt.Println("\nSIGNATURES:")
	for _, s := range sign.ListAll() {
		fmt.Println(s.Alg())
	}

	fmt.Println("\nHASHES:")
	for _, h := range hash.ListAll() {
		fmt.Println(h.Alg())
	}

	return nil
}
