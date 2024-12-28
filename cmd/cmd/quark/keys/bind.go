package keys

import (
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/spf13/cobra"
)

var bindArgs struct {
	keyID crypto.ID
}

func init() {
	Bind.Flags().VarP(cmdio.IDFlagValue{ID: &bindArgs.keyID}, "key", "k", "key ID")
}

// Bind command.
var Bind = &cobra.Command{
	Use:       "bind {id|key}",
	Short:     "Bind the subkey or identity",
	GroupID:   GroupID,
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgs: []string{"id", "key"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var key *app.Key
		var err error
		a := app.FromContext(cmd.Context())
		if bindArgs.keyID.IsEmpty() {
			var keys []*app.Key
			keys, err = a.List(nil, true)
			if err != nil {
				return err
			}
			key, err = interactive.SelectKey("Select a key", keys)
		} else {
			key, err = a.Load(app.ID(bindArgs.keyID))
		}
		if err != nil {
			return err
		}

		if args[0] == "id" {
			return bindID(key)
		}
		return bindKey(key)
	},
}

func bindID(k *app.Key) error {
	name, err := cmdio.Prompt("Enter name", "", nil)
	if err != nil {
		return err
	}
	email, err := cmdio.Prompt("Enter email", "", nil)
	if err != nil {
		return err
	}
	comment, err := cmdio.Prompt("Enter comment", "", nil)
	if err != nil {
		return err
	}
	return k.BindID(app.Identity{
		Name:    name,
		Email:   email,
		Comment: comment,
	}, 0, cmdio.PassphraseFunc("Enter passphrase to bind the identity"))
}

func bindKey(k *app.Key) error {
	i, err := cmdio.Select("Select key usage", []string{
		"Encryption",
		"Signing",
	})
	if err != nil {
		return err
	}
	exp, err := interactive.Expires("Select an expiration time")
	if err != nil {
		return err
	}
	if i == 0 {
		return bindKEM(k, exp)
	}
	return bindSign(k, exp)
}

func bindKEM(k *app.Key, exp int64) error {
	scheme, err := interactive.SelectScheme("Select a key algorithm", kem.ListAll, kem.ByName)
	if err != nil {
		return err
	}
	return k.BindKEM(scheme, exp, cmdio.PassphraseFunc("Enter passphrase to bind the key"))
}

func bindSign(k *app.Key, exp int64) error {
	scheme, err := interactive.SelectScheme("Select a key algorithm", sign.ListAll, sign.ByName)
	if err != nil {
		return err
	}
	return k.BindSign(scheme, exp, cmdio.PassphraseFunc("Enter passphrase to bind the key"))
}
