package enc

import (
	"io"
	"path/filepath"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

const messageExt = ".quark"

// EncryptCMD is the command to encrypt a message.
var EncryptCMD = &cli.Command{
	Name:     "encrypt",
	Aliases:  []string{"enc"},
	Category: "encrypt/decrypt",
	Usage:    "encrypt and sign",
	Description: "If the input file is provided it overrides the standard input. If the output file is:\n" +
		"\t- not provided: adds .quark extension to input file name\n" +
		"\t- empty: overrides the standard output with specified file\n" +
		"\t- '-': does not override standard output.",
	ArgsUsage: "[input file] [output file]",
	Flags: append(cmdio.IOFlags(),
		&cli.StringFlag{
			Name:    "recipient",
			Usage:   "encrypt for given `KEYSET` (if not provided, the message will be unencrypted)",
			Aliases: []string{"r"},
		},
		&cli.BoolFlag{
			Name:    "no-sign",
			Usage:   "do not sign",
			Aliases: []string{"n"},
		},
		&cli.BoolFlag{
			Name:    "clear-sign",
			Usage:   "sign the message without encryption",
			Aliases: []string{"c"},
		},
		&cli.StringFlag{
			Name:        "key",
			Usage:       "sign with given private `KEYSET`",
			Aliases:     []string{"k"},
			DefaultText: "default keyset",
		},
		&cli.BoolFlag{
			Name:    "symmetric",
			Usage:   "use symmetric encryption",
			Aliases: []string{"s"},
		},
	),
	Action: func(c *cli.Context) (err error) {
		recipient := c.String("recipient")
		noSign := c.Bool("no-sign")
		key := c.String("key")
		symmetric := c.Bool("symmetric")
		if recipient == "" && !c.Bool("clear-sign") {
			return cli.Exit("omit the recipient is only allowed with the clear-sign flag", 1)
		}

		if symmetric {
			err = cmdio.WithPassphrase("message encryption passphrase")
			if err != nil {
				return err
			}
		}

		input, output, err := cmdio.CustomIO(c.Args().First(), c.Args().Get(1), func(in string) string {
			return filepath.Base(in) + messageExt
		})

		data, err := io.ReadAll(input.Raw())
		if err != nil {
			return err
		}

		return encrypt(output, data, recipient, !noSign, key)
	},
}

func findPrivate(query string) (quark.Private, error) {
	if query == "" {
		return keyring.Default()
	}
	return keyring.FindPrivate(query)
}

func encrypt(out cmdio.Output, data []byte, recipient string, sign bool, signWith string) (err error) {
	var privKS quark.Private
	if sign {
		privKS, err = findPrivate(signWith)
		if err != nil {
			return err
		}
	}

	var pubKS quark.Public
	if recipient != "" {
		pubKS, err = keyring.Find(recipient)
		if err != nil {
			return err
		}
	}

	msg, err := quark.NewMessage(data, pubKS, privKS)
	if err != nil {
		return err
	}

	return out.Write(&msg)
}
