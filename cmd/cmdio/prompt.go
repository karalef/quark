package cmdio

import (
	"errors"
	"io"
	"strings"

	"github.com/manifoldco/promptui"
)

// RequestPassphrase prompts the user for a passphrase.
func RequestPassphrase(prompt string, empty ...bool) (string, error) {
	return TTY(func(in io.ReadCloser, out io.WriteCloser) (string, error) {
		pass := promptui.Prompt{
			Label:       prompt,
			Mask:        '*',
			HideEntered: true,
			Validate: func(input string) error {
				if len(input) == 0 && (len(empty) == 0 || !empty[0]) {
					return errors.New("passphrase must be non-empty")
				}
				return nil
			},
			Stdin:  in,
			Stdout: out,
		}
		return pass.Run()
	})
}

// Prompt prompts the user for input.
func Prompt(prompt, def string, validate func(string) error) (string, error) {
	return TTY(func(in io.ReadCloser, out io.WriteCloser) (string, error) {
		p := promptui.Prompt{
			Label:    prompt,
			Default:  def,
			Validate: validate,
			Stdin:    in,
			Stdout:   out,
		}
		return p.Run()
	})
}

// Confirm prompts the user for yes or no input.
// Actually just checks the input for "y".
func Confirm(prompt string, def ...bool) (bool, error) {
	resp, err := TTY(func(in io.ReadCloser, out io.WriteCloser) (string, error) {
		p := promptui.Prompt{
			Label:     prompt,
			IsConfirm: true,
			Stdin:     in,
			Stdout:    out,
		}
		return p.Run()
	})
	if err != nil {
		return false, err
	}
	resp = string(strings.ToLower(strings.TrimSpace(resp)))
	return resp == "y", nil
}

// PromptFunc is a function that prompts the user for input.
type PromptFunc = func() (string, error)

// PassphraseFunc returns a function that prompts the user for a passphrase.
func PassphraseFunc(prompt string, empty ...bool) PromptFunc {
	return func() (string, error) {
		return RequestPassphrase(prompt, empty...)
	}
}

// Select prompts the user for a selection from a list of items.
func Select(prompt string, items []string) (int, error) {
	if len(items) == 0 {
		return 0, errors.New("no items")
	}
	if len(items) == 1 {
		return 0, nil
	}
	return TTY(func(in io.ReadCloser, out io.WriteCloser) (int, error) {
		s := promptui.Select{
			Label:  prompt,
			Items:  items,
			Stdin:  in,
			Stdout: out,
		}
		i, _, err := s.Run()
		return i, err
	})
}
