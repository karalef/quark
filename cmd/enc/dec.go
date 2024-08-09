package enc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/message"
	"github.com/urfave/cli/v2"
)

// DecryptCMD is the command to decrypt a message.
var DecryptCMD = &cli.Command{
	Name:     "decrypt",
	Aliases:  []string{"dec"},
	Category: "encrypt/decrypt",
	Usage:    "decrypt and verify messages",
	Description: "If the input file is provided it overrides the standard input. If the output file is:\n" +
		"\t- not provided: adds .quark extension to input file name\n" +
		"\t- empty: overrides the standard output with specified file\n" +
		"\t- '-': does not override standard output.",
	ArgsUsage: "[input file] [output file]",
	Flags:     cmdio.IOFlags(),
	Action: func(ctx *cli.Context) (err error) {
		input, output, err := cmdio.CustomIO(ctx.Args().First(), c.Args().Get(1), func(in string) string {
			return strings.TrimSuffix(filepath.Base(in), messageExt)
		})

		obj, err := cmdio.Read()
		if err != nil {
			return err
		}
		if obj.PacketTag() != message.PacketTagMessage {
			return cli.Exit("input is not a message, but a '"+obj.PacketTag().String()+"'", 1)
		}
		msg := obj.(*message.Message)

		ks := ctx.Context.Value(keystore.ContextKey).(keystore.Keystore)

		if msg.Header.Encryption != nil {
			err = decrypt(ks, msg)
			if err != nil {
				return err
			}
		}

		cmdio.Status()
		if msg.Signature == nil {
			cmdio.Status(msg.Type().String(), "message")
		} else if msg.Signature.IsValid() {
			cmdio.Status(verify(msg.Signature.ID, msg.Data, msg.Signature.Signature))
		} else {
			cmdio.Status("invalid message signature: " + msg.Signature.Error())
		}

		_, err = output.Raw().Write(msg.Data)
		return err
	},
}

func decrypt(ks keystore.Keystore, msg *message.Message) error {
	id := msg.Header.Encryption.ID
	if !id.IsEmpty() {
		return cli.Exit("symmetric-only encryption is not supported", 1)
	}
	privKS, err := ks.Find(keystore.ByID(id))
	if err != nil {
		return err
	}
	msg.Decrypt()
	msg.Data, err = quark.Decrypt(msg.Data[:0], msg.Data, msg.Encryption, privKS)
	return err
}

func verify(sender quark.ID, data []byte, sig []byte) string {
	pubKS, err := keyring.ByID(sender.String())
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
