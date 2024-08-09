package enc

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/encaps"
	"github.com/karalef/quark/message"
	"github.com/karalef/quark/message/compress"
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
			Name:        "compression",
			Usage:       "compression `ALGORITHM{:LVL}`",
			DefaultText: "no compression",
		},
		&cli.StringFlag{
			Name:    "recipient",
			Usage:   "encrypt for given `KEY` (if not provided, the message will be unencrypted)",
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
			Usage:       "sign with given private `KEY`",
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
		compression, lvl, err := parseCompression(c.String("compression"))
		if err != nil {
			return err
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

		return encrypt(output, data, recipient, !noSign, key, compression, lvl)
	},
}

func parseCompression(v string) (compress.Compression, int, error) {
	if v == "" {
		return nil, 0, nil
	}
	alg, lvlStr, ok := strings.Cut(v, ":")
	var lvl int
	var err error
	if ok {
		lvl, err = strconv.Atoi(lvlStr)
		if err != nil {
			return nil, 0, cli.Exit("invalid compression level", 1)
		}
	}

	c := compress.ByName(alg)
	if c == nil {
		return nil, 0, cli.Exit(fmt.Errorf("unknown compression algorithm: %s\navailable^ %s",
			alg, strings.Join(compress.ListAll(), ", ")), 1)
	}

	return c, lvl, nil
}

func findPrivate(query string) (quark.Private, error) {
	if query == "" {
		return keyring.Default()
	}
	return keyring.FindPrivate(query)
}

func encrypt(out cmdio.Output, data []byte, recipient string, sign bool, signWith string, comp compress.Compression, lvl int) (err error) {
	var privKS quark.Private
	if sign {
		privKS, err = findPrivate(signWith)
		if err != nil {
			return err
		}
	}

	var pk encaps.PublicKey
	if recipient != "" {
		pubKS, err = keyring.Find(recipient)
		if err != nil {
			return err
		}
	}

	opts := []message.Opt{
		message.WithCompression(comp, uint(lvl)),
		message.WithEncryption(pk),
	}
	if sign {
		opts = append(opts, message.WithSignature(sk))
	}
	msg, err := message.New(bytes.NewReader(data), opts...)
	if err != nil {
		return err
	}

	return out.Write(msg)
}
