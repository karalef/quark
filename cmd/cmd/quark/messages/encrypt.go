package messages

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/cmdio/interactive"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/extensions/message"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/extensions/subkey"
	"github.com/spf13/cobra"
)

type Compression struct {
	Comp compress.Compression
	Lvl  uint
}

type compressionFlagValue struct{ Comp *Compression }

func (compressionFlagValue) String() string { return "" }
func (compressionFlagValue) Type() string   { return "compression" }
func (v compressionFlagValue) Set(s string) error {
	if s == "" {
		return nil
	}

	comp := Compression{}
	alg, lvlStr, ok := strings.Cut(s, ":")
	if ok {
		lvl, err := strconv.ParseUint(lvlStr, 10, 8)
		if err != nil {
			return errors.New("invalid compression level")
		}
		comp.Lvl = uint(lvl)
	}
	var err error
	comp.Comp, err = compress.ByName(alg)
	if err == nil {
		*v.Comp = comp
	}
	return err
}

type xofFlagger struct{}

func (xofFlagger) Type() string                        { return "XOF" }
func (xofFlagger) ByName(s string) (xof.Scheme, error) { return xof.ByName(s) }

type xofFlagValue = cmdio.SchemeFlagValue[xof.Scheme, xofFlagger]

var encryptFlags struct {
	key    crypto.ID
	nosign bool

	recipient  crypto.ID
	passphrase bool
	noenc      bool

	cipher aead.Scheme
	kdf    kdf.Scheme
	xof    xof.Scheme
	comp   Compression
}

func init() {
	flags := Encrypt.Flags()

	cmdio.IOFlags(flags)

	flags.VarP(cmdio.IDFlagValue{ID: &encryptFlags.key}, "key", "k", "key to sign with")
	flags.BoolVar(&encryptFlags.nosign, "nosign", false, "do not sign the message")

	flags.VarP(cmdio.IDFlagValue{ID: &encryptFlags.recipient}, "recipient", "r", "key to encrypt with")
	flags.BoolVarP(&encryptFlags.passphrase, "passphrase", "p", false, "use a passphrase to encrypt the key")
	flags.BoolVarP(&encryptFlags.noenc, "noencrypt", "n", false, "do not encrypt the message")

	flags.Var(cmdio.AEADFlagValue{Scheme: &encryptFlags.cipher}, "cipher", "encryption algorithm")
	flags.Var(cmdio.KDFFlagValue{Scheme: &encryptFlags.kdf}, "kdf", "key derivation function")
	flags.Var(xofFlagValue{Scheme: &encryptFlags.xof}, "xof", "xof algorithm")
	flags.VarP(compressionFlagValue{Comp: &encryptFlags.comp}, "compression", "c", "compression algorithm")
}

// Encrypt command.
var Encrypt = &cobra.Command{
	Use:     "encrypt [inputFile] [outputFile]",
	Short:   "encrypt and sign",
	GroupID: GroupID,
	Long: "Encrypts the message and signs it.\n" +
		"\nIf the input file is provided it overrides the standard input. If the output file is:\n" +
		"\t- not provided: adds .quark extension to input file name\n" +
		"\t- not empty: overrides the standard output with specified file\n" +
		"\t- '-': does not override standard output.",
	Aliases: []string{"enc"},
	Args:    cobra.RangeArgs(0, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		input, output, err := cmdio.ArgsIO(args, func(in string) string {
			return filepath.Base(in) + messageExt
		})
		if err != nil {
			return err
		}
		a := app.FromContext(cmd.Context())
		var opts []message.Opt

		// signature
		if !encryptFlags.nosign {
			var sub crypto.Key
			if !encryptFlags.key.IsEmpty() {
				err = a.VisitAll(func(key *app.Key) (stop bool) {
					key.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
						sub = s.Data.Key
						if sub.ID() != encryptFlags.key {
							return false
						}
						if s.Type != subkey.TypeSignKey {
							cmdio.Println("Key is not a signing key")
							os.Exit(1)
						}
						stop = true
						return true
					})
					return
				}, true)
				if err != nil {
					return err
				}
			} else {
				available, err := a.List(func(k *app.Key) bool {
					hasSign := false
					k.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
						hasSign = s.Type == subkey.TypeSignKey
						return hasSign
					})
					return hasSign
				}, true)
				if err != nil {
					return err
				}
				key, err := interactive.SelectKey("Select a sender", available)
				if err != nil {
					return err
				}
				var subs []subkey.Subkey
				key.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
					if s.Type == subkey.TypeSignKey {
						subs = append(subs, s.Data)
					}
					return false
				})
				sel, err := interactive.SelectSubkey("Select a key to sign with", subs)
				if err != nil {
					return err
				}
				sub = sel.Key
			}
			subSK, err := a.LoadSignSecret(sub.ID(), cmdio.PassphraseFunc("Enter the passphrase to decrypt the private key"))
			if err != nil {
				return err
			}
			opts = append(opts, message.WithSignature(subSK))
		}

		// encryption
		if !encryptFlags.noenc {
			if !encryptFlags.recipient.IsEmpty() {
				var sub crypto.Key
				err = a.VisitAll(func(key *app.Key) (stop bool) {
					key.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
						sub = s.Data.Key
						if sub.ID() != encryptFlags.recipient {
							return false
						}
						if s.Type != subkey.TypeKEMKey {
							cmdio.Println("Key is not a KEM key")
							os.Exit(1)
						}
						stop = true
						return true
					})
					return
				}, false)
				if err != nil {
					return err
				}
				scheme, err := interactive.SelectSecret(encryptFlags.cipher, encryptFlags.xof)
				if err != nil {
					return err
				}
				opts = append(opts, message.WithEncryption(sub.(kem.PublicKey), scheme))
			} else if encryptFlags.passphrase {
				scheme, err := interactive.SelectPassword(encryptFlags.cipher, encryptFlags.kdf)
				if err != nil {
					return err
				}
				pass, err := cmdio.RequestPassphrase("Enter the passphrase to encrypt the message")
				if err != nil {
					return err
				}
				opts = append(opts, message.WithPassword(pass, a.PassphraseParams(scheme)))
			} else {
				available, err := a.List(func(k *app.Key) bool {
					hasKEM := false
					k.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
						hasKEM = s.Type == subkey.TypeKEMKey
						return hasKEM
					})
					return hasKEM
				}, false)
				if err != nil {
					return err
				}
				key, err := interactive.SelectKey("Select a recepient", available)
				if err != nil {
					return err
				}
				var subs []subkey.Subkey
				key.VisitSubkeys(func(s quark.Certificate[subkey.Subkey]) bool {
					if s.Type == subkey.TypeKEMKey {
						subs = append(subs, s.Data)
					}
					return false
				})
				sub, err := interactive.SelectSubkey("Select a key to encrypt with", subs)
				if err != nil {
					return err
				}
				scheme, err := interactive.SelectSecret(encryptFlags.cipher, encryptFlags.xof)
				if err != nil {
					return err
				}
				opts = append(opts, message.WithEncryption(sub.Key.(kem.PublicKey), scheme))
			}
		}

		if encryptFlags.comp.Comp != nil {
			opts = append(opts, message.WithCompression(encryptFlags.comp.Comp, encryptFlags.comp.Lvl))
		}

		reader := io.Reader(input.Raw())

		if input.IsTerm() {
			cmdio.Println("Enter a message:")
			if output.IsTerm() {
				// since the message packs the part before reading input
				// it overlaps the prompt and input entering.
				reader, err = input.RawReader()
				if err != nil {
					return err
				}
			}
		}

		msg, err := message.New(reader, opts...)
		if err != nil {
			return err
		}
		return output.Write(msg)
	},
}
