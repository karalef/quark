package hash

import (
	"io"
	"sort"
	"strings"

	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/pkg/crockford"
	"github.com/spf13/cobra"
)

func init() {
	Hash.AddCommand(List)

	cmdio.IORawFlags(Hash.Flags())
}

var Hash = &cobra.Command{
	Use:   "hash ([algorithm|all])",
	Short: "hash the data",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || args[0] == "all" {
			return hashAll(cmdio.Input.Raw())
		}

		sch, err := hash.ByName(args[0])
		if err != nil {
			return err
		}
		h := sch.New()
		_, err = io.Copy(h, cmdio.Input.Raw())
		if err != nil {
			return err
		}
		_, err = cmdio.Output.Raw().Write(h.Sum(nil))
		return err
	},
}

func listSchemes() []hash.Scheme {
	schemes := hash.ListSchemes()
	sort.Slice(schemes, func(i, j int) bool {
		l, r := schemes[i].Name(), schemes[j].Name()
		ln, _, _ := strings.Cut(l, "_")
		rn, _, _ := strings.Cut(r, "_")
		if ln != rn {
			return l < r
		}
		return schemes[i].Size() < schemes[j].Size()
	})
	return schemes
}

func hashAll(input io.Reader) error {
	schemes := listSchemes()
	maxNameLen := 0
	mh := multiHasher{hashes: make([]hash.State, len(schemes))}
	for i, s := range schemes {
		mh.hashes[i] = s.New()
		maxNameLen = max(maxNameLen, len(s.Name()))
	}
	_, err := io.Copy(mh, input)
	if err != nil {
		return err
	}
	for i, h := range mh.hashes {
		name := schemes[i].Name()
		padding := maxNameLen - len(name)
		cmdio.Printf("%s%s: %s\n", strings.Repeat(" ", padding), name, crockford.Upper.EncodeToString(h.Sum(nil)))
	}
	return nil
}

type multiHasher struct {
	hashes []hash.State
}

func (m multiHasher) Write(p []byte) (n int, err error) {
	for _, w := range m.hashes {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}
