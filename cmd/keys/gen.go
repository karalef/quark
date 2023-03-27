package keys

import (
	"fmt"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cipher"
	"github.com/karalef/quark/cmd/storage"
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

		err = WritePrivFile(storage.PrivateKeysFS(), ks)
		if err != nil {
			return err
		}
		fmt.Println("generated keyset", KeyID(ks))
		return nil
	},
}

var DefaultScheme = quark.Scheme{
	KEM:    kem.Kyber768.Scheme(),
	Cipher: cipher.XChacha20Poly1305.Scheme(),
	Sign:   sign.Dilithium3.Scheme(),
	Hash:   quark.HashSHA256.Scheme(),
}.String()

func GenerateKeySet(scheme string, name, email string) (quark.PrivateKeyset, error) {
	sch, err := quark.ParseScheme(scheme)
	if err != nil {
		return nil, err
	}

	return quark.Generate(nil, quark.Identity{name, email}, sch)
}

func PrintSchemes() {
	fmt.Println("All available algorithms")

	fmt.Println()
	fmt.Println("KEM:")
	fmt.Println(kem.Kyber512, kem.Kyber512.Scheme().SharedKeySize())
	fmt.Println(kem.Kyber768, kem.Kyber768.Scheme().SharedKeySize())
	fmt.Println(kem.Kyber1024, kem.Kyber1024.Scheme().SharedKeySize())
	fmt.Println(kem.Frodo, kem.Frodo.Scheme().SharedKeySize())

	fmt.Println()
	fmt.Println("CIPHERS:")
	fmt.Println(cipher.AESGCM128, cipher.AESGCM128.Scheme().KeySize())
	fmt.Println(cipher.AESGCM192, cipher.AESGCM192.Scheme().KeySize())
	fmt.Println(cipher.AESGCM256, cipher.AESGCM256.Scheme().KeySize())
	fmt.Println(cipher.XChacha20Poly1305, cipher.XChacha20Poly1305.Scheme().KeySize())

	fmt.Println()
	fmt.Println("SIGNATURES:")
	fmt.Println(sign.Dilithium2)
	fmt.Println(sign.Dilithium3)

	fmt.Println()
	fmt.Println("HASHES:")
	fmt.Println(quark.HashSHA256)
	fmt.Println(quark.HashSHA384)
	fmt.Println(quark.HashSHA512)
}
