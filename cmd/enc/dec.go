package enc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/karalef/quark/pack"
	"github.com/urfave/cli/v2"
)

var DecryptCMD = &cli.Command{
	Name:        "decrypt",
	Aliases:     []string{"dec"},
	Category:    "encrypt/decrypt",
	Usage:       "decrypt and verify messages",
	Description: "If the file is passed as argument it overrides the default input and output.\nBe careful when using file argument because the output file can be rewritten\n(output file will be with the same name but without quark extension).",
	ArgsUsage:   "<input file>",
	Action: func(c *cli.Context) (err error) {
		input := cmdio.Input()
		output := cmdio.RawOutput()

		if c.Args().Present() { // override stdin and stdout
			name := c.Args().First()
			input, err = cmdio.CustomInput(name)
			if err != nil {
				return err
			}
			defer input.Close()

			name = strings.TrimSuffix(filepath.Base(name), messageExt)
			output, err = cmdio.CustomRawOutput(name)
			if err != nil {
				return err
			}
			defer output.Close()
		}

		msg, err := pack.DecodeExact[quark.Message](input, pack.TagMessage)
		if err != nil {
			return err
		}

		if msg.Type().IsEncrypted() {
			privKS, err := keyring.FindPrivate(msg.Recipient.String())
			if err != nil {
				return err
			}
			msg.Data, err = quark.Decrypt(msg.Data, msg.Key, privKS)
			if err != nil {
				return err
			}
		}

		if !msg.Type().IsSigned() {
			cmdio.Status(msg.Type().String(), "message")
		} else {
			cmdio.Status(verify(msg.Sender, msg.Data, msg.Signature))
		}

		_, err = output.Write(msg.Data)
		return err
	},
}

func verify(fp quark.Fingerprint, data []byte, sig []byte) string {
	pubKS, err := keyring.ByID(fp.ID().String())
	if err != nil {
		return "sender cannot be verified: " + err.Error()
	}

	ok, err := quark.Verify(data, sig, pubKS)
	if err != nil {
		return "sender cannot be verified: " + err.Error()
	}
	id := pubKS.Identity()
	if !ok {
		return fmt.Sprintf("signature mismatches the sender %s %s %s", pubKS.ID(), id.Name, id.Email)
	}
	return fmt.Sprintf("signature verified: %s %s %s", pubKS.ID(), id.Name, id.Email)
}
