package quark

import (
	"errors"
	"iter"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/pke"
)

// SecretSize finds the smallest plaintext size among all recipients.
// It also returns the recipients count and the biggest size to use padding.
// Panics if recipients is empty.
func SecretSize(recipients iter.Seq[pke.PublicKey]) (size, biggest int) {
	for recipient := range recipients {
		ptSize := recipient.Scheme().PlaintextSize()
		if size == 0 {
			size, biggest = ptSize, ptSize
			continue
		}
		size, biggest = min(size, ptSize), max(biggest, ptSize)
	}
	if size == 0 {
		panic("invalid secret size")
	}
	return
}

// NewGroupSecret generates a new secret for the group with size calculated
// for provided recipients.
func NewGroupSecret(recipients iter.Seq[pke.PublicKey]) (GroupSecret, []byte) {
	size, biggest := SecretSize(recipients)
	padded := crypto.Rand(biggest)
	secret := make([]byte, size)
	copy(secret, padded[:size])
	return GroupSecret(padded), secret
}

// GroupSecret contains a secret and padding for recipients.
type GroupSecret []byte

// EncryptFor encrypts a part of secret for recipient.
// Panics if the length of secret is less than the plaintext size of recipient.
func (gs GroupSecret) EncryptFor(recipient pke.PublicKey) ([]byte, error) {
	size := recipient.Scheme().PlaintextSize()
	return pke.Encrypt(recipient, gs[:size])
}

// ErrNotEncrypted is returned when there is no encyrpted secret for the recipient.
var ErrNotEncrypted = errors.New("there is no encrypted secret for the recipient")
