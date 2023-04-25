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
	},
	Action: func(c *cli.Context) (err error) {
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

		return encrypt(input, output, !c.Bool("no-sign"), c.String("key"), c.String("r"))
	},
}

func encrypt(in io.Reader, out io.Writer, sign bool, signWith string, recipient string) error {
	var privKS *quark.Private
	var err error
	if sign {
		if signWith == "" {
			privKS, err = keyring.Default()
		} else {
			privKS, err = keyring.FindPrivate(signWith)
		}
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
