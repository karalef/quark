package cmdio

import (
	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/scheme"
	"github.com/spf13/pflag"
)

// IFlags defines input flags.
func IFlags(f *pflag.FlagSet) {
	f.VarP(FileActFlag{Action: FileActionChangeInput}, "input", "i", "input `FILE` (override stdin)")
}

// OFlags defines output flags.
func OFlags(f *pflag.FlagSet) {
	f.BoolVarP(&Armor, "armor", "a", false, "use ascii-armored output")
	ORawFlags(f)
}

// ORawFlags defines raw output flags.
func ORawFlags(f *pflag.FlagSet) {
	f.VarP(FileActFlag{Action: FileActionChangeOutput}, "output", "o", "output `FILE` (override stdout)")
}

// IORawFlags defines input and raw output flags.
func IORawFlags(f *pflag.FlagSet) {
	IFlags(f)
	ORawFlags(f)
}

// IOFlags defines input and output flags.
func IOFlags(f *pflag.FlagSet) {
	IFlags(f)
	OFlags(f)
}

type FileActFlag struct {
	Action func(string) error
}

func (FileActFlag) String() string       { return "" }
func (FileActFlag) Type() string         { return "file" }
func (f FileActFlag) Set(s string) error { return f.Action(s) }

func FileActionChangeInput(path string) error {
	i, err := CustomInput(path)
	if err != nil {
		return err
	}
	Input = i
	return nil
}

func FileActionChangeOutput(path string) error {
	o, err := CustomOutput(path)
	if err != nil {
		return err
	}
	Output = o
	return nil
}

// ArgsIO accept input and output arguments and returns custom input and output.
//
// ioArgs                    | input    | output
// --------------------------+----------+-------
// [] || ["-"] || ["-", "-"] | stdin    | stdout
// ["-", "file.ext"]         | stdin    | file.ext
// ["file.ext"]              | file.ext | outputName("file.ext")
// ["file.ext", "-"]         | file.ext | stdout
// ["file.ext", "file2.ext"] | file.ext | file2.ext
func ArgsIO(ioArgs []string, outputName func(string) string) (input file, output file, err error) {
	input, output = Input, Output
	if len(ioArgs) == 0 || ioArgs[0] == "" {
		return
	}
	if ioArgs[0] != "-" { // override input
		input, err = CustomInput(ioArgs[0])
		if err != nil {
			return
		}
		if len(ioArgs) == 1 {
			output, err = CustomOutput(ioArgs[1])
			if err != nil {
				return
			}
		}
	}

	if len(ioArgs) < 2 {
		if outputName == nil {
			return
		}
		output, err = CustomOutput(outputName(ioArgs[0]))
		return
	}
	if ioArgs[1] != "-" { // override output
		output, err = CustomOutput(ioArgs[1])
	}
	return
}

var _ pflag.Value = (*SchemeFlagValue[aead.Scheme, AEADFlagger])(nil)

type SchemeFlagger[T scheme.Scheme] interface {
	Type() string
	ByName(string) (T, error)
}

type SchemeFlagValue[T scheme.Scheme, F SchemeFlagger[T]] struct{ Scheme *T }

func (v SchemeFlagValue[_, _]) String() string {
	if v.Scheme == nil || any(*v.Scheme) == nil {
		return ""
	}
	return (*v.Scheme).Name()
}
func (SchemeFlagValue[_, F]) Type() string { var f F; return f.Type() }

func (v SchemeFlagValue[T, F]) Set(s string) error {
	var f F
	scheme, err := f.ByName(s)
	if err != nil {
		return err
	}
	*v.Scheme = scheme
	return nil
}

type (
	AEADFlagValue = SchemeFlagValue[aead.Scheme, AEADFlagger]
	AEADFlagger   struct{}
)

func (AEADFlagger) Type() string                         { return "AEAD" }
func (AEADFlagger) ByName(s string) (aead.Scheme, error) { return aead.ByName(s) }

type (
	KDFFlagValue = SchemeFlagValue[kdf.Scheme, KDFFlagger]
	KDFFlagger   struct{}
)

func (KDFFlagger) Type() string                        { return "KDF" }
func (KDFFlagger) ByName(s string) (kdf.Scheme, error) { return kdf.ByName(s) }

type IDFlagValue struct{ ID *crypto.ID }

func (v IDFlagValue) String() string {
	if v.ID == nil || v.ID.IsEmpty() {
		return ""
	}
	return v.ID.String()
}

func (IDFlagValue) Type() string { return "ID" }

func (f IDFlagValue) Set(s string) error {
	id, err := app.ParseID(s)
	if err != nil {
		return err
	}
	*f.ID = id
	return nil
}
