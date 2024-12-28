package cmdio

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/karalef/quark/pack"
	"github.com/mattn/go-tty"
	"golang.org/x/term"
)

// Armor forces the armor output.
var Armor bool

var (
	Input  = file{os.Stdin}
	Output = file{os.Stdout}
)

// TTY calls the function with tty input and output.
func TTY[T any](f func(in io.ReadCloser, out io.WriteCloser) (T, error)) (T, error) {
	t, err := tty.Open()
	if err != nil {
		var empty T
		return empty, err
	}
	defer t.Close()
	return f(t.Input(), t.Output())
}

func isTerm(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

type file struct {
	f *os.File
}

func (f file) Raw() *os.File { return f.f }
func (f file) Close() error  { return f.f.Close() }
func (f file) IsTerm() bool  { return isTerm(f.f) }
func (f file) RawReader() (io.Reader, error) {
	if !f.IsTerm() {
		return f.f, nil
	}
	buf, err := io.ReadAll(f.f)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(buf), nil
}

func (f file) reader() (io.Reader, error) {
	r, err := f.RawReader()
	if err != nil {
		return nil, err
	}
	_, _, in, err := pack.Dearmor(r)
	return in, err
}

func (f file) Read() (pack.Packable, error) {
	r, err := f.reader()
	if err != nil {
		return nil, err
	}
	return pack.Unpack(r)
}

func (f file) Write(v pack.Packable) error {
	out := io.Writer(f.f)
	if Armor || isTerm(f.f) {
		armored, err := pack.ArmoredEncoder(out, v.PacketTag().BlockType(), nil)
		if err != nil {
			return err
		}
		defer armored.Close()
		out = armored
	}

	return pack.Pack(out, v)
}

// CustomInput opens the specified file and returns it as Input.
// If the path is empty, it returns the standard input.
func CustomInput(path string) (file, error) {
	if path == "" {
		return Input, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Input, err
	}
	return file{f}, nil
}

// CustomOutput opens the specified file and returns it as Output.
// If the path is empty, it returns the standard output.
func CustomOutput(path string) (file, error) {
	if path == "" {
		return Output, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Output, err
	}
	return file{f}, nil
}

// Print calls fmt.Fprint to stderr.
func Print(v ...any) { fmt.Fprint(os.Stderr, v...) }

// Println calls fmt.Fprintln to stderr.
func Println(v ...any) { fmt.Fprintln(os.Stderr, v...) }

// Printf calls fmt.Fprintf to stderr.
func Printf(format string, v ...any) { fmt.Fprintf(os.Stderr, format, v...) }
