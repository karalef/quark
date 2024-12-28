package hash

import (
	"strings"

	"github.com/karalef/quark-cmd/cmdio"
	"github.com/spf13/cobra"
)

var List = &cobra.Command{
	Use:   "list",
	Short: "list hash algorithms",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		schemes := listSchemes()
		l := len(schemes)
		var colWidths [4]uint8
		for i, s := range schemes {
			colWidths[i%4] = max(colWidths[i%4], uint8(len(s.Name())))
		}
		for i := 0; i < l; i += 4 {
			for c := 0; i+c < l && c < 4; c++ {
				name := schemes[i+c].Name()
				pad := colWidths[c] - uint8(len(name))
				cmdio.Print(name + strings.Repeat(" ", int(pad)+3))
			}
			cmdio.Println()
		}
		return nil
	},
}
