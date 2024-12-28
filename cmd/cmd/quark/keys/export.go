package keys

import (
	"errors"

	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/extensions/backup"
	"github.com/spf13/cobra"
)

var exportFlags struct {
	aead   aead.Scheme
	kdf    kdf.Scheme
	secret bool
}

func init() {
	flags := Export.Flags()

	cmdio.OFlags(flags)

	flags.BoolVarP(&exportFlags.secret, "secret", "s", false, "export private key")
	flags.Var(cmdio.AEADFlagValue{Scheme: &exportFlags.aead}, "aead", "aead encryption scheme")
	flags.Var(cmdio.KDFFlagValue{Scheme: &exportFlags.kdf}, "kdf", "key derivation function")
}

// Export command.
var Export = &cobra.Command{
	Use:     "export",
	Short:   "Export a key",
	GroupID: GroupID,
	Aliases: []string{"exp"},
	Args:    cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		output := cmdio.Output
		if len(args) > 1 {
			var err error
			output, err = cmdio.CustomOutput(args[1])
			if err != nil {
				return err
			}
		}

		a := app.FromContext(cmd.Context())
		ider := app.IDStr(args[0])
		key, err := a.Load(ider)
		if err != nil {
			return err
		}

		if !exportFlags.secret {
			return output.Write(key.Raw())
		}

		ok, err := key.IsPrivateExist()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("private key not found")
		}

		id, _ := ider.ID()
		sk, err := a.LoadSignSecret(id, cmdio.PassphraseFunc("Enter the passphrase to decrypt the private key"))
		if err != nil {
			return err
		}
		bd := backup.BackupData{
			Key:    key.Raw(),
			Secret: sk,
		}
		scheme, err := interactive.SelectPassword(exportFlags.aead, exportFlags.kdf)
		if err != nil {
			return err
		}
		pass, err := cmdio.RequestPassphrase("Enter the passphrase to encrypt the backup")
		if err != nil {
			return err
		}

		bu, err := backup.New(bd, pass, nil, a.PassphraseParams(scheme))
		if err != nil {
			return err
		}

		return output.Write(bu)
	},
}
