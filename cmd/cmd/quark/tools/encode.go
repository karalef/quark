package tools

import (
	"encoding/base64"
	"io"

	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/pkg/crockford"
	"github.com/spf13/cobra"
)

var endecodeFlags struct {
	decode bool
	nonl   bool
}

func init() {
	cmdio.IORawFlags(Base32.Flags())
	cmdio.IORawFlags(Base64.Flags())
	Base32.Flags().BoolVarP(&endecodeFlags.decode, "decode", "d", false, "decode data")
	Base64.Flags().BoolVarP(&endecodeFlags.decode, "decode", "d", false, "decode data")
	Base32.Flags().BoolVarP(&endecodeFlags.nonl, "no-newline", "n", false, "does not append a newline in terminal")
	Base64.Flags().BoolVarP(&endecodeFlags.nonl, "no-newline", "n", false, "does not append a newline in terminal")
}

var Base32 = &cobra.Command{
	Use:   "base32 [FILE]",
	Short: "Crockford's base32 encode or decode FILE, or standard input, to standard output",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return endecode(crockford.Upper, cmd, args)
	},
}

var Base64 = &cobra.Command{
	Use:   "base64 [FILE]",
	Short: "Base64 encode or decode FILE, or standard input, to standard output",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return endecode(base64.RawStdEncoding, cmd, args)
	},
}

type encoder interface {
	EncodeToString([]byte) string
	Decode([]byte, []byte) (int, error)
}

func endecode(encoder encoder, cmd *cobra.Command, args []string) error {
	in, out, err := cmdio.ArgsIO(args, nil)
	if err != nil {
		return err
	}
	src, err := io.ReadAll(in.Raw())
	if err != nil {
		return err
	}
	newline := out.IsTerm() && !endecodeFlags.nonl
	if !endecodeFlags.decode {
		s := encoder.EncodeToString(src)
		if newline {
			s += "\n"
		}
		_, err = out.Raw().WriteString(s)
		return err
	}

	i, err := encoder.Decode(src, src)
	if err != nil {
		return err
	}
	if newline {
		src[i] = '\n'
		i++
	}
	_, err = out.Raw().Write(src[:i])
	return err
}
