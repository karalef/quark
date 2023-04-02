package enc

import (
	"fmt"
	"os"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/keys"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

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
		privKS, err := keys.UsePrivate(c.String("k"))
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

		data, err := quark.Decrypt(msg.EncryptedData, msg.EncryptedKey, privKS)
		if err != nil {
			return err
		}

		if !msg.IsAnonymous() {
			pubKS, err := keys.UsePublic(keys.IDByFP(msg.Fingerprint))
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
			fmt.Fprintln(os.Stderr, "signature verified:", quark.KeysetIDOf(pubKS), pubKS.Identity().Name, pubKS.Identity().Email)
		} else {
			fmt.Fprintln(os.Stderr, "anonymous message")
		}

		return os.WriteFile(outputFile, data, 0600)
	},
}
