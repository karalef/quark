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
	Name:      "decrypt",
	Aliases:   []string{"d", "dec"},
	Category:  "encrypt/decrypt",
	Usage:     "decrypt and verify messages",
	ArgsUsage: "<input file>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "key",
			Usage:    "use given private keyset",
			Aliases:  []string{"k"},
			Required: true,
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
			return cli.NewExitError("missing input file", 1)
		}
		inputFile, err := os.Open(input)
		if err != nil {
			return err
		}
		defer inputFile.Close()

		msg, err := pack.UnpackMessage(inputFile)
		if err != nil {
			return err
		}

		privKS, err := keys.UsePrivate(c.String("key"))
		if err != nil {
			return err
		}
		data, err := quark.Decrypt(msg.EncryptedData, msg.EncryptedKey, privKS)
		if err != nil {
			return err
		}

		out := os.Stdout
		if outFile := c.String("out"); outFile != "" {
			out, err = os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
		}

		if msg.IsAnonymous() {
			fmt.Fprintln(os.Stderr, "anonymous message")
		} else {
			status := verify(msg.Fingerprint, data, msg.Signature)
			fmt.Fprint(os.Stderr, status, "\n\n")
		}

		_, err = out.Write(data)
		return err
	},
}

func verify(fp quark.Fingerprint, data []byte, sig []byte) string {
	pubKS, err := keys.UsePublic(keys.IDByFP(fp))
	if err != nil {
		return "sender cannot be verified"
	}

	ok, err := quark.Verify(data, sig, pubKS)
	if err != nil {
		return "sender cannot be verified: " + err.Error()
	}
	id := pubKS.Identity()
	if !ok {
		return fmt.Sprintf("signature mismatches the sender %s %s %s", quark.KeysetIDOf(pubKS).String(), id.Name, id.Email)
	}
	return fmt.Sprintf("signature verified: %s %s %s", quark.KeysetIDOf(pubKS).String(), id.Name, id.Email)
}
