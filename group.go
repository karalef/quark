package quark

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/pke"
)

// EncryptSecret encrypts a part of secret for recipient.
// Panics if the length of secret is less than the plaintext size of recipient.
func EncryptSecret(recipient pke.PublicKey, secret []byte) ([]byte, error) {
	size := recipient.Scheme().PlaintextSize()
	return pke.Encrypt(recipient, secret[:size])
}

// SecretSize finds the smallest plaintext size among all recipients.
// It also returns the biggest size to use padding.
// Panics if recipients is empty.
func SecretSize(recipients []pke.PublicKey) (size, biggest int) {
	if len(recipients) == 0 {
		panic("recipients is empty")
	}
	for _, recipient := range recipients {
		ptSize := recipient.Scheme().PlaintextSize()
		if size == 0 {
			size, biggest = ptSize, ptSize
			continue
		}
		size, biggest = min(size, ptSize), max(biggest, ptSize)
	}
	return
}

// EncryptGroupSecret generates a random shared secret and encrypts it for each
// recipient (in the same order). Panics if recipients is empty.
func EncryptGroupSecret(recipients []pke.PublicKey) ([]byte, [][]byte, error) {
	size, biggest := SecretSize(recipients)
	secrets := make([][]byte, len(recipients))

	padded := crypto.Rand(biggest)
	for i, recipient := range recipients {
		ct, err := EncryptSecret(recipient, padded)
		if err != nil {
			return nil, nil, err
		}
		secrets[i] = ct
	}

	return padded[:size:size], secrets, nil
}

// ErrNotEncrypted is returned when there is no encyrpted secret for the recipient.
var ErrNotEncrypted = errors.New("there is no encrypted secret for the recipient")
