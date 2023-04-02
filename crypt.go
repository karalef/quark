package quark

import (
	"crypto/rand"
	"io"
)

// Encrypt encrypts data for the public key.
func Encrypt(data []byte, to PublicKeyset) (cipherkey []byte, ciphertext []byte, err error) {
	cipherkey, cipher, err := to.Encapsulate()
	if err != nil {
		return nil, nil, err
	}

	ciphScheme := to.CipherScheme()

	ciphertext = make([]byte, ciphScheme.NonceSize(), ciphScheme.NonceSize()+len(data)+ciphScheme.Overhead())

	// read nonce
	if _, err = io.ReadFull(rand.Reader, ciphertext); err != nil {
		return nil, nil, err
	}

	ciphertext = cipher.Seal(ciphertext, ciphertext, data)

	return cipherkey, ciphertext, nil
}

// Decrypt decrypts data for the private key.
func Decrypt(ciphertext []byte, encryptedKey []byte, to PrivateKeyset) (data []byte, err error) {
	cipher, err := to.Decapsulate(encryptedKey)
	if err != nil {
		return nil, err
	}

	ciphScheme := to.CipherScheme()

	data = make([]byte, 0, len(ciphertext[ciphScheme.NonceSize():])+ciphScheme.Overhead())

	return cipher.Open(data, ciphertext[:ciphScheme.NonceSize()], ciphertext[ciphScheme.NonceSize():])
}
