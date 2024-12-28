package keys

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/extensions/backup"
	"github.com/spf13/cobra"
)

func init() {
	cmdio.IOFlags(Import.Flags())
}

// Import command.
var Import = &cobra.Command{
	Use:     "import [file]",
	Short:   "Import a key",
	GroupID: GroupID,
	Long:    "If the file is passed as argument it overrides the default input",
	Aliases: []string{"imp"},
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := cmdio.Input
		if len(args) > 0 { // override stdin
			var err error
			input, err = cmdio.CustomInput(args[0])
			if err != nil {
				return err
			}
		}

		v, err := input.Read()
		if err != nil {
			return err
		}

		app := app.FromContext(cmd.Context())

		switch t := v.PacketTag(); t {
		case backup.PacketTagBackup:
		case quark.PacketTagKey:
			return app.Import(v.(*quark.Key))
		default:
			return errors.New("invalid input packet: " + t.String())
		}

		pass, err := cmdio.RequestPassphrase("Enter the passphrase to decrypt the backup")
		if err != nil {
			return err
		}
		bd, err := v.(*backup.Backup).Decrypt(pass)
		if err != nil {
			return err
		}

		scheme, err := interactive.SelectPassword(genFlags.aead, genFlags.kdf)
		if err != nil {
			return err
		}
		pass, err = cmdio.RequestPassphrase("Enter the passphrase to encrypt private keys")
		if err != nil {
			return err
		}

		k, err := key.Encrypt(bd.Secret, pass, crypto.Rand(scheme.NonceSize()), app.PassphraseParams(scheme).New())
		if err != nil {
			return err
		}

		return app.Import(bd.Key, k)
	},
}
