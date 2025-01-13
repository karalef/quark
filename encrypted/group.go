package encrypted

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/pke"
)

// EncryptGroup generates a shared secret, encrypts it for each recipient and creates an authenticated stream cipher.
func EncryptGroup(scheme Secret, recipients []pke.PublicKey, nonce, associatedData []byte) (aead.Cipher, *GroupSecret, error) {
	ss, secrets, err := EncryptGroupSecret(recipients)
	if err != nil {
		return nil, nil, err
	}

	aead, err := scheme.Encrypter(nonce, ss, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &GroupSecret{
		Scheme:  scheme,
		Size:    uint(len(ss)),
		Secrets: secrets,
	}, err
}

// GroupSecret contains assymetrically encrypted shared secret for each recipient
// with symmetric encryption parameters.
type GroupSecret struct {
	// Secrets contains encrypted shared secrets related to recipients.
	Secrets `msgpack:"secrets"`

	// Symmetric encryption scheme.
	Scheme Secret `msgpack:"scheme"`

	// Size of the shared secret.
	Size uint `msgpack:"size"`
}

// DecryptTo creates an authenticated cipher for provided recipient.
func (e GroupSecret) DecryptTo(recipient pke.PrivateKey, nonce, ad []byte) (aead.Cipher, error) {
	secret, err := e.DecryptSecret(recipient, e.Size)
	if err != nil {
		return nil, err
	}
	return e.Scheme.Decrypter(nonce, secret, ad)
}

// GroupSecretSize finds the smallest plaintext size among all recipients.
// It also returns the biggest size to use random padding.
func GroupSecretSize(recipients []pke.PublicKey) (size, biggest int) {
	if len(recipients) == 0 {
		panic("empty recipients")
	}
	for _, recipient := range recipients {
		ptSize := recipient.Scheme().(pke.Scheme).PlaintextSize()
		if size == 0 {
			size, biggest = ptSize, ptSize
			continue
		}
		size = min(size, ptSize)
		biggest = max(biggest, ptSize)
	}
	return
}

// EncryptGroupSecret generates a shared secret and encrypts it for each recipient.
func EncryptGroupSecret(recipients []pke.PublicKey) ([]byte, Secrets, error) {
	secretSize, maxSize := GroupSecretSize(recipients)
	secrets := make(Secrets, len(recipients))

	secretBuf := crypto.Rand(maxSize)
	for _, recipient := range recipients {
		size := recipient.Scheme().(pke.Scheme).PlaintextSize()
		ct, err := pke.Encrypt(recipient, secretBuf[:size])
		if err != nil {
			return nil, nil, err
		}
		secrets[recipient.Fingerprint()] = ct
	}

	return secretBuf[:secretSize], secrets, nil
}

// Secrets contains encrypted shared secrets related to recipients.
type Secrets map[crypto.Fingerprint][]byte

// IsEncryptedFor returns true if the Secrets contains secret for provided recipient.
func (s Secrets) IsEncryptedFor(recipient pke.PublicKey) bool {
	_, ok := s[recipient.Fingerprint()]
	return ok
}

// DecryptSecret decrypts shared secret for provided recipient.
func (s Secrets) DecryptSecret(recipient pke.PrivateKey, size uint) ([]byte, error) {
	secret, ok := s[recipient.Fingerprint()]
	if !ok {
		return nil, ErrNotEncrypted
	}
	pt, err := recipient.Decrypt(secret)
	if err != nil {
		return nil, err
	}
	return pt[:size:size], nil
}

// ErrNotEncrypted is returned when there is no encyrpted secret for the recipient.
var ErrNotEncrypted = errors.New("there is no encyrpted secret for the recipient")
