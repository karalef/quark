package cmdio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

func getTerm() int {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fd = -1
	}
	return fd
}

// RequestPassphrase prompts the user for a passphrase.
func RequestPassphrase(prompt string) (string, error) {
	fd := getTerm()
	if fd < 0 {
		return "", errors.New("passphrase cannot be read from non-terminal input")
	}
	fmt.Fprintf(os.Stderr, "Enter %s: ", prompt)
	passphrase, err := term.ReadPassword(fd)
	fmt.Fprint(os.Stderr, "\n")
	if err != nil {
		return "", err
	}
	if len(passphrase) == 0 {
		return "", errors.New("passphrase must be non-empty")
	}
	return string(passphrase), nil
}

// PassphraseFunc returns a function that prompts the user for a passphrase.
func PassphraseFunc(prompt string) func() (string, error) {
	return func() (string, error) {
		return RequestPassphrase(prompt)
	}
}

// YesNo prompts the user for yes or no input.
// Actually just checks the input for "y" or "yes".
func YesNo(prompt string) (bool, error) {
	Statusf("%s (yes/no): ", prompt)
	fmt.Scan()
	response, err := readUntil(os.Stdin, '\n')
	if err != nil {
		return false, err
	}

	resp := string(bytes.ToLower(bytes.TrimSpace(response)))
	return resp == "y" || resp == "yes", nil
}

// readUntil reads until the specified byte is found or EOF is reached.
func readUntil(r io.Reader, b byte) ([]byte, error) {
	var buf [1]byte
	var ret []byte

	for {
		n, err := r.Read(buf[:])
		if n > 0 && buf[0] == b || err == io.EOF {
			return ret, nil
		}
		if err != nil {
			return ret, err
		}
		ret = append(ret, buf[0])
	}
}
