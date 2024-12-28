package messages

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/message"
	"github.com/karalef/quark/extensions/subkey"
	"github.com/spf13/cobra"
)

func init() {
	cmdio.IOFlags(Decrypt.Flags())
}

// Decrypt command.
var Decrypt = &cobra.Command{
	Use:     "decrypt [input file] [output file]",
	GroupID: GroupID,
	Aliases: []string{"dec"},
	Args:    cobra.RangeArgs(0, 2),
	Short:   "decrypt and verify messages",
	Long: "Decrypts the message and verifies the signature.\n" +
		"\nIf the input file is provided it overrides the standard input. If the output file is:\n" +
		"\t- not provided: adds .quark extension to input file name\n" +
		"\t- not empty: overrides the standard output with specified file\n" +
		"\t- '-': does not override standard output.",
	RunE: func(cmd *cobra.Command, args []string) error {
		input, output, err := cmdio.ArgsIO(args, func(in string) string {
			return strings.TrimSuffix(filepath.Base(in), messageExt)
		})
		if err != nil {
			return err
		}

		v, err := input.Read()
		if err != nil {
			return err
		}

		msg, ok := v.(*message.Message)
		if !ok || v.PacketTag() != message.PacketTagMessage {
			return errors.New("not a message")
		}

		a := app.FromContext(cmd.Context())
		dec := message.Decrypt{}

		if !msg.Header.Sender.IsEmpty() {
			err = a.VisitAll(func(key *app.Key) (stop bool) {
				key.VisitSubkeys(func(sub quark.Certificate[subkey.Subkey]) bool {
					key := sub.Data.Key
					if key.Fingerprint() != msg.Header.Sender {
						return false
					}
					if sub.Type != subkey.TypeSignKey {
						cmdio.Println("Key is not a signing key")
						os.Exit(1)
					}
					dec.Issuer = key.(sign.PublicKey)
					stop = true
					return true
				})
				return
			}, false)
			if err != nil {
				return err
			}
		}
		if msg.Header.IsEncrypted() {
			if msg.Header.IsPassphrased() {
				dec.Password, err = cmdio.RequestPassphrase("Enter the passphrase to decrypt the message")
			} else {
				err = a.VisitAll(func(key *app.Key) (stop bool) {
					key.VisitSubkeys(func(sub quark.Certificate[subkey.Subkey]) bool {
						key := sub.Data.Key
						if key.Fingerprint() != msg.Header.Encryption.Recepient {
							return false
						}
						if sub.Type != subkey.TypeKEMKey {
							cmdio.Println("Key is not a KEM key")
							os.Exit(1)
						}
						dec.Recipient, err = a.LoadKEMSecret(key.ID(), cmdio.PassphraseFunc("Enter passphrase to decrypt the key"))
						if err != nil {
							cmdio.Println("Failed to load key")
							os.Exit(1)
						}
						stop = true
						return true
					})
					return
				}, true)
			}
			if err != nil {
				return err
			}
		}

		return msg.Decrypt(output.Raw(), dec)
	},
}
