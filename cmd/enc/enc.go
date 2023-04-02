package enc

import (
	"fmt"
	"io"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keys"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var EncryptCMD = &cli.Command{
	Name:     "enc",
	Aliases:  []string{"e", "encrypt"},
	Category: "encrypt/decrypt",
	Usage:    "encrypt and sign",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "r",
			Usage:    "encrypt for given keyset",
			Aliases:  []string{"recipient"},
			Required: true,
		},
		&cli.StringFlag{
			Name:    "k",
			Usage:   "sign with given private keyset",
			Aliases: []string{"key"},
		},
		&cli.StringFlag{
			Name:     "i",
			Usage:    "input file",
			Aliases:  []string{"input", "file"},
			Required: true,
		},
	},
	Action: func(c *cli.Context) error {
		out := io.Writer(os.Stdout)
		if c.Args().Present() {
			var err error
			out, err = os.OpenFile(c.Args().First(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
		}

		input, err := os.Open(c.String("i"))
		if err != nil {
			return err
		}
		defer input.Close()

		return encrypt(input, out, c.String("k"), c.String("r"))
	},
}

func encrypt(in io.Reader, out io.Writer, priv, pub string) error {
	privKS, _ := keys.UsePrivate(priv)
	if privKS == nil {
		fmt.Fprintln(os.Stderr, "anonymous message\n")
	}

	pubKS, err := keys.UsePublic(pub)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	msg, err := quark.EncryptMessage(data, pubKS, privKS)
	if err != nil {
		return err
	}

	return pack.Message(out, msg)
}
