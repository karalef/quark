package enc

import (
	"fmt"
	"io"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var EncryptCMD = &cli.Command{
	Name:      "encrypt",
	Aliases:   []string{"e", "enc"},
	Category:  "encrypt/decrypt",
	Usage:     "encrypt and sign",
	ArgsUsage: "<input file>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "recipient",
			Usage:    "encrypt for given keyset",
			Aliases:  []string{"r"},
			Required: true,
		},
		&cli.BoolFlag{
			Name:    "no-sign",
			Usage:   "do not sign",
			Aliases: []string{"n"},
		},
		&cli.StringFlag{
			Name:    "key",
			Usage:   "sign with given private keyset",
			Aliases: []string{"k"},
		},
		&cli.StringFlag{
			Name:        "out",
			Usage:       "output file",
			Aliases:     []string{"o", "output"},
			DefaultText: "/dev/stdout",
		},
	},
	Action: func(c *cli.Context) error {
		var input = c.Args().First()
		if input == "" {
			return cli.Exit("missing input file", 1)
		}
		inputFile, err := os.Open(input)
		if err != nil {
			return err
		}
		defer inputFile.Close()

		out := os.Stdout
		if outFile := c.String("out"); outFile != "" {
			out, err = os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
		}
		return encrypt(inputFile, out, !c.Bool("no-sign"), c.String("key"), c.String("r"), out == os.Stdout)
	},
}

func encrypt(in io.Reader, out io.Writer, sign bool, priv, pub string, armor bool) error {
	var privKS *quark.Private
	var err error
	if sign {
		if priv == "" {
			privKS, err = keyring.Default()
		}
		privKS, err = keyring.FindPrivate(priv)
	} else {
		fmt.Fprintln(os.Stderr, "anonymous message")
	}
	if err != nil {
		return err
	}

	pubKS, err := keyring.Find(pub)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	msg, err := quark.EncryptPlain(data, pubKS, privKS)
	if err != nil {
		return err
	}

	if armor {
		wc, err := pack.ArmoredEncoder(out, pack.BlockTypeMessage, nil)
		if err != nil {
			return err
		}
		defer wc.Close()
		out = wc
	}

	return pack.Message(out, msg)
}
