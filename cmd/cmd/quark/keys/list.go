package keys

import (
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/utils"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/extensions/subkey"
	"github.com/spf13/cobra"
)

var listFlags struct {
	fp bool
}

func init() {
	flags := List.Flags()
	flags.BoolVarP(&listFlags.fp, "fingerprint", "f", false, "print keys fingerprint")
}

// List command.
var List = &cobra.Command{
	Use:     "list",
	Short:   "List keys",
	GroupID: GroupID,
	Aliases: []string{"ls"},
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		keys, err := app.FromContext(cmd.Context()).List(nil, false)
		if err != nil {
			return err
		}
		for i := range keys {
			printKey(keys[i], listFlags.fp)
			if i < len(keys)-1 {
				cmdio.Println()
			}
		}
		return nil
	},
}

func printKey(key *app.Key, fp bool) {
	created, v := key.Validity()
	cmdio.Printf("pub  %s %s %s\n", key.ID(), key.Scheme().Name(), utils.FormatUnix(created))
	printFP(key, fp)
	printValidity(v)

	key.VisitIdentities(func(c quark.Certificate[app.Identity]) (stop bool) {
		printIdentity(c)
		printValidity(c.Validity())
		return false
	})

	key.VisitSubkeys(func(c quark.Certificate[subkey.Subkey]) (stop bool) {
		printSubkey(c.Validity().Created, c.Data.Key, fp)
		printValidity(c.Validity())
		return false
	})

	key.VisitDatabinds(func(c quark.RawCertificate) (stop bool) {
		printBind(c)
		return false
	})
}

func printValidity(v quark.Validity) {
	if v.IsRevoked() {
		cmdio.Printf("     revoked at %s because %s\n", utils.FormatUnix(v.Created), v.Reason)
	} else if v.IsExpired(time.Now().Unix()) {
		cmdio.Printf("     expired at %s\n", utils.FormatUnix(v.Expires))
	} else if v.Expires > 0 {
		cmdio.Printf("     expires at %s\n", utils.FormatUnix(v.Expires))
	}
}

func printSubkey(t int64, sub crypto.Key, fp bool) {
	cmdio.Printf("sub  %s %s %s\n", sub.ID(), sub.Scheme().Name(), utils.FormatUnix(t))
	printFP(sub, fp)
}

func printIdentity(i quark.Certificate[app.Identity]) {
	cmdio.Printf("uid  %s %s\n", i.ID.ID().String(), i.Data.String())
}

func printBind(b quark.RawCertificate) {
	cmdio.Printf("unk  %s %s\n", b.ID.ID().String(), b.Type)
}

func printFP(key interface{ Fingerprint() crypto.Fingerprint }, p bool) {
	if p {
		cmdio.Println("    ", key.Fingerprint().String())
	}
}
