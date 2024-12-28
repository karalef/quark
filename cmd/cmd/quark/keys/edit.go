package keys

import (
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/extensions/subkey"
	"github.com/spf13/cobra"
)

var Edit = &cobra.Command{
	Use:     "edit [id]",
	Short:   "Edit the key",
	GroupID: GroupID,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a := app.FromContext(cmd.Context())
		var key *app.Key
		var err error
		if len(args) > 0 {
			key, err = a.Load(app.IDStr(args[0]))
		} else {
			keys, err := a.List(nil, true)
			if err != nil {
				return err
			}
			key, err = interactive.SelectKey("Select a key", keys)
		}
		if err != nil {
			return err
		}
		var subkeys []quark.Certificate[subkey.Subkey]
		key.VisitSubkeys(func(c quark.Certificate[subkey.Subkey]) (stop bool) {
			subkeys = append(subkeys, c)
			return false
		})
		var idents []quark.Certificate[app.Identity]
		key.VisitIdentities(func(c quark.Certificate[app.Identity]) (stop bool) {
			idents = append(idents, c)
			return false
		})
		selections := make([]string, 1, 3)
		selections[0] = "Key"
		if len(subkeys) > 0 {
			selections = append(selections, "Subkey")
		}
		if len(idents) > 0 {
			selections = append(selections, "Identity")
		}
		whatEdit, err := cmdio.Select("What to edit", selections)
		if err != nil {
			return err
		}
		switch whatEdit {
		default:
			return nil
		case 0:
			return editKey(a, key)
		case 1:
			return editSubkey(key, subkeys)
		case 2:
			return editIdentity(key, idents)
		}
	},
}

func editKey(a *app.App, k *app.Key) error {
	actions := make([]string, 1, 3)
	actions[0] = "Delete key"
	_, v := k.Validity()
	if !v.IsRevoked() {
		actions = append(actions, "Revoke key")
		if !v.IsExpired(time.Now().Unix()) {
			actions = append(actions, "Change expiration time")
		}
	}
	wtd, err := cmdio.Select("What to do", actions)
	if err != nil {
		return err
	}
	switch wtd {
	default:
		return nil
	case 0:
		return a.Delete(app.ID(k.ID()), func(withSecret bool) (bool, error) {
			quest := "Are you sure you want to delete " + k.ID().String()
			if withSecret {
				quest += " (the private keys will also be deleted)"
			}
			return cmdio.Confirm(quest)
		})
	case 1:
		reason, err := cmdio.Prompt("Enter the revocation reason", "", nil)
		if err != nil {
			return err
		}
		return k.Revoke(reason, cmdio.PassphraseFunc("Enter passphrase to revoke the key"))
	case 2:
	}
	exp, err := interactive.Expires("Select a new expiration time")
	if err != nil {
		return err
	}
	return k.ChangeExpiry(exp, cmdio.PassphraseFunc("Enter passphrase to edit the key"))
}

func editSubkey(k *app.Key, subkeys []quark.Certificate[subkey.Subkey]) error {
	subkeyStrs := make([]string, len(subkeys))
	for i, subkey := range subkeys {
		s := subkey.ID.ID().String() + " (" + subkey.Data.Scheme().Name() + ")"
		v := subkey.Validity()
		if v.IsRevoked() {
			s = "[revoked] " + s
		} else if v.IsExpired(time.Now().Unix()) {
			s = "[expired] " + s
		}
		subkeyStrs[i] = s
	}
	selected, err := cmdio.Select("Select a subkey", subkeyStrs)
	if err != nil {
		return err
	}
	subkey := subkeys[selected]

	actions := make([]string, 1, 3)
	actions[0] = "Delete subkey"
	if !subkey.Validity().IsRevoked() {
		actions = append(actions, "Revoke subkey")
		if !subkey.Validity().IsExpired(time.Now().Unix()) {
			actions = append(actions, "Change expiration time")
		}
	}
	wtd, err := cmdio.Select("What to do", actions)
	if err != nil {
		return err
	}
	ider := app.FP(subkey.ID)
	switch wtd {
	default:
		return nil
	case 0:
		return k.Unbind(ider)
	case 1:
		reason, err := cmdio.Prompt("Enter the revocation reason", "", nil)
		if err != nil {
			return err
		}
		return k.RevokeBinding(ider, reason, cmdio.PassphraseFunc("Enter passphrase to revoke the subkey"))
	case 2:
		exp, err := interactive.Expires("Select a new expiration time")
		if err != nil {
			return err
		}
		return k.Rebind(ider, exp, cmdio.PassphraseFunc("Enter passphrase to edit the subkey"))
	}
}

func editIdentity(k *app.Key, idents []quark.Certificate[app.Identity]) error {
	identStrs := make([]string, len(idents))
	for i, ident := range idents {
		s := ident.Data.String()
		v := ident.Validity()
		if v.IsRevoked() {
			s = "[revoked] " + s
		} else if v.IsExpired(time.Now().Unix()) {
			s = "[expired] " + s
		}
		identStrs[i] = s
	}
	selected, err := cmdio.Select("Select an identity", identStrs)
	if err != nil {
		return err
	}
	ident := idents[selected]

	actions := make([]string, 1, 4)
	actions[0] = "Delete identity"
	if !ident.Validity().IsRevoked() {
		actions = append(actions, "Revoke identity")
		if !ident.Validity().IsExpired(time.Now().Unix()) {
			actions = append(actions, "Change expiration time")
		}
	}

	wtd, err := cmdio.Select("What to do", actions)
	if err != nil {
		return err
	}
	ider := app.FP(ident.ID)
	switch wtd {
	default:
		return nil
	case 0:
		return k.Unbind(ider)
	case 1:
		reason, err := cmdio.Prompt("Enter the revocation reason", "", nil)
		if err != nil {
			return err
		}
		return k.RevokeBinding(ider, reason, cmdio.PassphraseFunc("Enter passphrase to revoke the identity"))
	case 2:
		exp, err := interactive.Expires("Select a new expiration time")
		if err != nil {
			return err
		}
		return k.Rebind(ider, exp, cmdio.PassphraseFunc("Enter passphrase to edit the key"))
	}
}
