package cmdio

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/karalef/quark/pack"
	"golang.org/x/term"
)

var (
	armor      bool
	compressor pack.Compressor
	passphrase string
)

// Input represents a cmd input.
type Input interface {
	Raw() *os.File
	Close() error

	// Read reads the value from input.
	Read() (pack.Tag, pack.Packable, error)

	reader() (io.Reader, error)
}

// Output represents a cmd output.
type Output interface {
	Raw() *os.File
	Close() error

	// Write writes the specified value to the output.
	Write(pack.Packable) error
}

type file struct {
	*os.File
}

func (f file) Raw() *os.File { return f.File }

func (f file) Close() error { return f.File.Close() }

func (f file) reader() (io.Reader, error) {
	if !term.IsTerminal(int(f.File.Fd())) {
		return f.File, nil
	}

	// since the input is a terminal it can overlap the prompt or output (e.g. passphrase prompt).
	buf, err := io.ReadAll(f.File)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(buf), nil
}

func (f file) Read() (pack.Tag, pack.Packable, error) {
	r, err := f.reader()
	if err != nil {
		return 0, nil, err
	}
	return pack.Unpack(r, pack.WithPassphrase(PassphraseFunc("passphrase")))
}

func (f file) Write(v pack.Packable) error {
	var opts []pack.Option
	if armor {
		opts = append(opts, pack.WithArmor(nil))
	}
	if compressor != nil {
		opts = append(opts, pack.WithCompression(compressor))
	}
	if passphrase != "" {
		opts = append(opts, pack.WithEncryption(passphrase, nil))
	}

	return pack.Pack(f.File, v, opts...)
}

// WithPassphrase requests the passphrase and creates packing option.
func WithPassphrase(prompt string) error {
	p, err := RequestPassphrase(prompt)
	if err != nil {
		return err
	}
	passphrase = p
	return nil
}

// GetInput returns the standard input.
func GetInput() Input { return file{os.Stdin} }

// GetOutput returns the standard output.
func GetOutput() Output { return file{os.Stdout} }

// CustomInput opens the specified file and returns it as Input.
// If the path is empty, it returns the standard input.
func CustomInput(path string) (Input, error) {
	if path == "" {
		return GetInput(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return file{f}, nil
}

// CustomOutput opens the specified file and returns it as Output.
// If the path is empty, it returns the standard output.
func CustomOutput(path string) (Output, error) {
	if path == "" {
		return GetOutput(), nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return file{f}, nil
}

// ReadExact reads the value with specified type from the provided input.
func ReadExact[T pack.Packable](in Input) (v T, err error) {
	r, err := in.reader()
	if err != nil {
		return
	}
	return pack.UnpackExact[T](r, pack.WithPassphrase(PassphraseFunc("passphrase")))
}

// Write is an alias of GetInput().Write.
func Write(v pack.Packable) error {
	return GetOutput().Write(v)
}

// Read is an alias of GetInput().Read.
func Read() (pack.Tag, pack.Packable, error) {
	return GetInput().Read()
}

// Status prints a status message.
func Status(v ...any) {
	fmt.Fprintln(os.Stderr, v...)
}

// Statusf prints a status message with format.
func Statusf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}
