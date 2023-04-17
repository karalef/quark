package keys

import (
	"fmt"

	"github.com/karalef/quark"
	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
	"github.com/urfave/cli/v2"
)

var Gen = &cli.Command{
	Name:     "gen",
	Usage:    "generate a new keyset",
	Category: "key management",
	Subcommands: []*cli.Command{
		{
			Name:    "list",
			Usage:   "list all available schemes",
			Aliases: []string{"l", "list-schemes"},
			Action: func(c *cli.Context) error {
				PrintSchemes()
				return nil
			},
		},
	},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "n",
			Usage:   "name",
			Aliases: []string{"name"},
		},
		&cli.StringFlag{
			Name:    "e",
			Usage:   "email",
			Aliases: []string{"email"},
		},
	},
	Action: func(c *cli.Context) error {
		scheme := c.Args().First()
		if scheme == "" {
			scheme = DefaultScheme
		}
		name := c.String("n")
		email := c.String("e")

		ks, err := GenerateKeySet(scheme, name, email)
		if err != nil {
			return err
		}

		err = ImportPrivate(ks)
		if err != nil {
			return err
		}
		fmt.Println("generated keyset", quark.KeysetIDOf(ks))
		return nil
	},
}

var DefaultScheme = quark.Scheme{
	KEM:  kem.Kyber768XChaCha20Poly1305.Scheme(),
	Sign: sign.Dilithium3ED448.Scheme(),
	Hash: hash.SHA256.Scheme(),
}.String()

func GenerateKeySet(scheme string, name, email string) (quark.PrivateKeyset, error) {
	sch, err := quark.ParseScheme(scheme)
	if err != nil {
		return nil, err
	}

	return quark.Generate(quark.Identity{name, email}, sch)
}

func PrintSchemes() {
	fmt.Println("All available algorithms")

	fmt.Println("\nKEM:")
	for _, k := range kem.ListAll() {
		fmt.Printf("%s", k.Alg())
	}

	fmt.Println("\nSIGNATURES:")
	for _, s := range sign.ListAll() {
		fmt.Println(s.Alg())
	}

	fmt.Println("\nHASHES:")
	for _, h := range hash.ListAll() {
		fmt.Println(h.Alg())
	}
}
