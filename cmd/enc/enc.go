package enc

import (
	"io"
	"path/filepath"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

const messageExt = ".quark"

var EncryptCMD = &cli.Command{
	Name:        "encrypt",
	Aliases:     []string{"enc"},
	Category:    "encrypt/decrypt",
	Usage:       "encrypt and sign",
	Description: "If the file is passed as argument it overrides the default input and output and encrypts the file instead of a message",
	ArgsUsage:   "<input file>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "recipient",
			Usage:   "encrypt for given keyset",
			Aliases: []string{"r"},
		},
		&cli.BoolFlag{
			Name:    "no-sign",
			Usage:   "do not sign",
			Aliases: []string{"n"},
		},
		&cli.BoolFlag{
			Name:    "clear-sign",
			Usage:   "clear signature (disable message encryption, but require signature)",
			Aliases: []string{"c"},
		},
		&cli.StringFlag{
			Name:    "key",
			Usage:   "sign with given private keyset",
			Aliases: []string{"k"},
		},
	},
	Action: func(c *cli.Context) (err error) {
		sign := !c.Bool("no-sign")
		cs := c.Bool("clear-sign")
		if !sign && cs {
			return cli.Exit("--no-sign and --clear-sign are mutually exclusive", 1)
		}
		input := cmdio.Input()
		var output io.WriteCloser

		if c.Args().Present() { // override stdin and stdout
			name := c.Args().First()
			input, err = cmdio.CustomInput(name)
			if err != nil {
				return err
			}
			name = filepath.Base(name) + messageExt
			output, err = cmdio.CustomOutput(name, pack.BlockTypeMessage)
		} else {
			output, err = cmdio.Output(pack.BlockTypeMessage)
		}
		if err != nil {
			return err
		}
		defer output.Close()

		if cs {
			return clearSign(input, output, c.String("key"))
		}

		return encrypt(input, output, sign, c.String("key"), c.String("r"))
	},
}

func findPrivate(query string) (*quark.Private, error) {
	if query == "" {
		return keyring.Default()
	}
	return keyring.FindPrivate(query)
}

func encrypt(in io.Reader, out io.Writer, sign bool, signWith string, recipient string) (err error) {
	var privKS *quark.Private
	if sign {
		privKS, err = findPrivate(signWith)
	}
	if err != nil {
		return err
	}

	pubKS, err := keyring.Find(recipient)
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

	return pack.Message(out, msg)
}

func clearSign(in io.Reader, out io.Writer, signWith string) error {
	privKS, err := findPrivate(signWith)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	msg, err := quark.ClearSign(data, privKS)
	if err != nil {
		return err
	}

	return pack.Message(out, msg)
}
