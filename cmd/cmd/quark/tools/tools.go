package tools

import (
	"io"
	"strconv"

	"github.com/karalef/quark-cmd/cmd/quark/tools/callibrate"
	"github.com/karalef/quark-cmd/cmd/quark/tools/hash"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/crypto"
	"github.com/spf13/cobra"
)

func init() {
	Tools.AddCommand(callibrate.Callibrate)
	Tools.AddCommand(hash.Hash)
	Tools.AddCommand(rnd)
	Tools.AddCommand(Base32)
	Tools.AddCommand(Base64)
}

var Tools = &cobra.Command{
	Use:   "tools",
	Short: "provides various tools",
}

func init() {
	cmdio.IORawFlags(rnd.Flags())
}

var rnd = &cobra.Command{
	Use:   "rand [size]",
	Short: "reads random bytes from OS secure random source",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		size := 32
		if len(args) > 0 {
			size, err = strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			if size < 1 {
				return
			}
		}
		_, err = io.CopyN(cmdio.Output.Raw(), crypto.Reader(nil), int64(size))
		return
	},
}
