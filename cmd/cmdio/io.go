package cmdio

import (
	"fmt"
	"io"
	"os"

	"github.com/karalef/quark/pack"
)

var armor bool

// Input returns the standard input.
func Input() *os.File { return os.Stdin }

// RawOutput returns the standard output.
func RawOutput() *os.File { return os.Stdout }

// Output returns the armored WriteCloser with the specified block type.
// If armor is disabled, it returns stdout.
func Output(blockType string) (io.WriteCloser, error) {
	if !armor {
		return os.Stdout, nil
	}
	return pack.ArmoredEncoder(os.Stdout, blockType, nil)
}

// CustomInput opens the specified file or returns stdin if the path is empty.
func CustomInput(path string) (*os.File, error) {
	if path == "" {
		return os.Stdin, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// CustomRawOutput opens the specified file or returns stdout if the path is empty.
func CustomRawOutput(path string) (*os.File, error) {
	if path == "" {
		return os.Stdout, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// CustomOutput opens the specified file with armor encoding or returns armored stdout if the path is empty.
// If armor is disabled, it returns file as is.
func CustomOutput(path string, blockType string) (io.WriteCloser, error) {
	f, err := CustomRawOutput(path)
	if err != nil {
		return nil, err
	}
	if !armor {
		return f, nil
	}
	return pack.ArmoredEncoder(f, blockType, nil)
}

// Status prints a status message.
func Status(v ...any) {
	fmt.Fprintln(os.Stderr, v...)
}

// Statusf prints a status message with format.
func Statusf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}
