package enc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keyring"
	"github.com/urfave/cli/v2"
)

// DecryptCMD is the command to decrypt a message.
var DecryptCMD = &cli.Command{
	Name:        "decrypt",
	Aliases:     []string{"dec"},
	Category:    "encrypt/decrypt",
	Usage:       "decrypt and verify messages",
	Description: "If the file is passed as argument it overrides the default input and output (removing .quark extension from input file name).",
	ArgsUsage:   "[input file] [output file]",
	Flags:       cmdio.IOFlags(),
	Action: func(c *cli.Context) (err error) {
		input, output, err := cmdio.CustomIO(c.Args().First(), c.Args().Get(1), func(in string) string {
			return strings.TrimSuffix(filepath.Base(in), messageExt)
		})

		msg, err := cmdio.ReadExact[*quark.Message](input)
		if err != nil {
			return err
		}

		if msg.Type().IsEncrypted() {
			err = decrypt(msg)
			if err != nil {
				return err
			}
		}

		if !msg.Type().IsSigned() {
			cmdio.Status(msg.Type().String(), "message")
		} else {
			cmdio.Status(verify(msg.Sender, msg.Data, msg.Signature))
		}

		_, err = output.Raw().Write(msg.Data)
		return err
	},
}

func decrypt(msg *quark.Message) error {
	privKS, err := keyring.FindPrivate(msg.Recipient.ID().String())
	if err != nil {
		return err
	}
	msg.Data, err = quark.Decrypt(msg.Data, msg.Key, privKS)
	return err
}

func verify(fp quark.Fingerprint, data []byte, sig []byte) string {
	pubKS, err := keyring.ByID(fp.ID().String())
	if err != nil {
		return "sender cannot be verified: " + err.Error()
	}

	ok, err := pubKS.Sign().Verify(data, sig)
	if err != nil {
		return "sender cannot be verified: " + err.Error()
	}
	id := pubKS.Identity()
	if !ok {
		return fmt.Sprintf("signature mismatches the sender %s %s %s", pubKS.ID(), id.Name, id.Email)
	}
	return fmt.Sprintf("signature verified: %s %s %s", pubKS.ID(), id.Name, id.Email)
}
