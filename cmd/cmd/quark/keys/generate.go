package keys

import (
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/spf13/cobra"
)

var genFlags struct {
	aead aead.Scheme
	kdf  kdf.Scheme
}

func init() {
	Gen.Flags().Var(cmdio.AEADFlagValue{Scheme: &genFlags.aead}, "aead", "aead algorithm")
	Gen.Flags().Var(cmdio.KDFFlagValue{Scheme: &genFlags.kdf}, "kdf", "key derivation function")
}

// Gen command.
var Gen = &cobra.Command{
	Use:       "generate [algorithm] [--aead cipherAlgorithm] [--kdf KDF]",
	Short:     "Generate a new key",
	GroupID:   GroupID,
	Aliases:   []string{"gen"},
	Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
	ValidArgs: sign.ListAll(),
	RunE: func(cmd *cobra.Command, args []string) error {
		scheme, err := interactive.StringOrSelect(args, "Select a key algorithm", sign.ListAll, sign.ByName)
		if err != nil {
			return err
		}
		exp, err := interactive.Expires("Select an expiration time")
		if err != nil {
			return err
		}
		password, err := interactive.SelectPassword(genFlags.aead, genFlags.kdf)
		if err != nil {
			return err
		}

		id, err := app.FromContext(cmd.Context()).Generate(
			scheme, exp, password,
			cmdio.PassphraseFunc("Enter the passphrase to encrypt the private key"),
		)
		if err != nil {
			return err
		}

		cmdio.Println("generated key", id.String())

		return nil
	},
}
