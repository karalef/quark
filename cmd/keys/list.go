package keys

import (
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/bind"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/urfave/cli/v2"
)

// ListCMD is the command to list identities.
var ListCMD = &cli.Command{
	Name:     "list",
	Aliases:  []string{"ls"},
	Usage:    "list identities",
	Category: "key management",
	Action: func(c *cli.Context) error {
		ks := c.Context.Value(keystore.ContextKey).(keystore.Keystore)
		ids, err := ks.List("")
		if err != nil {
			return err
		}
		for i := range ids {
			printIdent(ids[i])
		}
		return nil
	},
}

func printIdent(id *quark.Identity) {
	created, v := id.Validity()
	cmdio.Statusf("%s %s\n%s\n%s\t", id.ID(), id.Key().Scheme().Name(), id.Fingerprint(), time.Unix(created, 0))
	if v.Revoked != 0 {
		cmdio.Statusf("revoked at %s because %s\n", time.Unix(v.Revoked, 0), v.Reason)
	} else {
		cmdio.Statusf("valid until %s\n", time.Unix(v.Expires, 0))
	}

	cmdio.Status()

	bindings := id.Bindings()
	for _, b := range bindings {
		cmdio.Statusf("%s %s %s\n", b.ID.String(), b.Group, b.Type)
		v := b.Signature.Validity
		if v.Revoked != 0 {
			cmdio.Statusf("revoked at %s because %s\n", time.Unix(v.Revoked, 0), v.Reason)
		} else {
			cmdio.Statusf("signed by %s and valid until %s\n", b.Signature.Issuer.ID().String(), time.Unix(v.Expires, 0))
		}
		switch b.Type {
		case bind.TypeSignKey:
			pk, err := bind.DecodeKey(b)
			if err != nil {
				cmdio.Status(err)
				continue
			}
			cmdio.Statusf("%s\n", pk.Fingerprint())
		case bind.TypeKEMKey:
			pk, err := bind.DecodeKEM(b)
			if err != nil {
				cmdio.Status(err)
				continue
			}
			cmdio.Statusf("%s\n", pk.Fingerprint())
		default:
			if b.Type.InGroup(quark.BindType(bind.GroupID)) {
				cmdio.Statusf("%s\n", b.Data)
			} else {
				cmdio.Statusf("unnknown type %s\n", b.Type)
			}
		}
	}

	cmdio.Status()
}
