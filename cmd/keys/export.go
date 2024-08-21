package keys

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/urfave/cli/v2"
)

// ExportCMD is the command to export a public keyset to a file.
var ExportCMD = &cli.Command{
	Name:      "export",
	Usage:     "export an identity to a file",
	Category:  "key management",
	Aliases:   []string{"exp"},
	ArgsUsage: "<id|string> [output file]",
	Flags: append(cmdio.OutputFlags(),
		&cli.BoolFlag{
			Name:    "secret",
			Usage:   "export private key",
			Aliases: []string{"s"},
		},
	),
	Action: export,
}

func export(ctx *cli.Context) (err error) {
	if !ctx.Args().Present() {
		return cli.ShowCommandHelp(ctx, "export")
	}

	output := cmdio.GetOutput()
	if out := ctx.Args().Get(1); out != "" {
		output, err = cmdio.CustomOutput(out)
		if err != nil {
			return
		}
	}

	ks := ctx.Context.Value(keystore.ContextKey).(keystore.Keystore)

	query := ctx.Args().First()

	id, err := ks.Find(query)
	if err != nil {
		return err
	}

	if ctx.Bool("secret") {
		sk, err := ks.PrivKeyByID(id.ID(), cmdio.PassphraseFunc("enter the passphrase to decrypt the private key"))
		if err != nil {
			return err
		}
		pass, err := cmdio.RequestPassphrase("enter the passphrase to backup the private key")
		if err != nil {
			return err
		}
		ek, err := quark.EncryptKey(sk, pass, password.Build(
			aead.Build(cipher.AESCTR256, mac.BLAKE2b128),
			kdf.Argon2i,
		), &kdf.Argon2Params{
			Rounds:  3,
			Memory:  32 * 1024,
			Threads: 4,
		})
		if err != nil {
			return err
		}
		id.WithPrivateKey(ek)
	}

	return output.Write(id)
}
