package enc

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keys"
	"github.com/karalef/quark/cmd/storage"
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
			Name:     "k",
			Usage:    "sign with given private keyset",
			Aliases:  []string{"key"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "i",
			Usage:    "input file",
			Aliases:  []string{"input", "file"},
			Required: true,
		},
	},
	Action: func(c *cli.Context) error {
		var outputFile = c.Args().First()
		if outputFile == "" {
			return cli.NewExitError("missing output file", 1)
		}
		privKS, err := keys.LoadPriv(storage.PrivateKeysFS(), c.String("k"))
		if err != nil {
			return err
		}

		pubKS, err := keys.LoadPub(storage.PublicKeysFS(), c.String("r"))
		if err != nil {
			return err
		}

		data, err := os.ReadFile(c.String("i"))
		if err != nil {
			return err
		}

		msg, err := quark.EncryptMessage(data, pubKS, privKS)
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer outFile.Close()

		return pack.Message(outFile, msg)
	},
}

var DecryptCMD = &cli.Command{
	Name:     "dec",
	Aliases:  []string{"d", "decrypt"},
	Category: "encrypt/decrypt",
	Usage:    "decrypt and verify messages",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "k",
			Usage:   "use given private keyset",
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
		var outputFile = c.Args().First()
		if outputFile == "" {
			return cli.NewExitError("missing output file", 1)
		}
		privKS, err := keys.LoadPriv(storage.PrivateKeysFS(), c.String("k"))
		if err != nil {
			return err
		}

		inputFile, err := os.Open(c.String("i"))
		if err != nil {
			return err
		}
		defer inputFile.Close()

		msg, err := pack.UnpackMessage(inputFile)
		if err != nil {
			return err
		}

		data, err := quark.DecryptMessage(msg, privKS)
		if err != nil {
			return err
		}

		if !msg.IsAnonymous() {
			pubKS, err := keys.LoadPub(storage.PublicKeysFS(), keys.KeyIDByFingerprint(msg.Fingerprint))
			if err != nil {
				return cli.NewExitError("sender cannot be verified", 1)
			}

			ok, err := pubKS.Verify(data, msg.Signature)
			if err != nil {
				return cli.NewExitError("sender cannot be verified: "+err.Error(), 1)
			}
			if !ok {
				return cli.NewExitError("sender cannot be verified", 1)
			}
			fmt.Println("signature verified:", keys.KeyID(pubKS), pubKS.Identity().Name, pubKS.Identity().Email)
		}

		return os.WriteFile(outputFile, data, 0600)
	},
}

func readFile(name string) ([]byte, fs.FileInfo, error) {
	d, err := os.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}

	fi, err := os.Stat(name)
	return d, fi, err
}
