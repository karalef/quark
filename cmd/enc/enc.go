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

// EncryptCMD is the command to encrypt a message.
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
			Usage:   "encrypt for given keyset (if not provided, the message will be unecrypted)",
			Aliases: []string{"r"},
		},
		&cli.BoolFlag{
			Name:    "no-sign",
			Usage:   "do not sign",
			Aliases: []string{"n"},
		},
		&cli.StringFlag{
			Name:        "key",
			Usage:       "sign with given private keyset",
			Aliases:     []string{"k"},
			DefaultText: "default keyset",
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

		data, err := io.ReadAll(input)
		if err != nil {
			return err
		}

		recipient := c.String("recipient")
		noSign := c.Bool("no-sign")
		key := c.String("key")

		return encrypt(output, data, recipient, !noSign, key)
	},
}

func findPrivate(query string) (*quark.Private, error) {
	if query == "" {
		return keyring.Default()
	}
	return keyring.FindPrivate(query)
}

func encrypt(out io.Writer, data []byte, recipient string, sign bool, signWith string) (err error) {
	var privKS *quark.Private
	if sign {
		privKS, err = findPrivate(signWith)
	}
	if err != nil {
		return err
	}

	var msg quark.Message
	if recipient == "" {
		msg, err = quark.SignMessage(data, privKS)
	} else {
		var pubKS *quark.Public
		pubKS, err = keyring.Find(recipient)
		if err != nil {
			return err
		}
		msg, err = quark.EncryptMessage(data, pubKS, privKS)
	}
	if err != nil {
		return err
	}

	return pack.Message(out, msg)
}
