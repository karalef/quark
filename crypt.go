package quark

import (
	"crypto/rand"
	"io"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
)

// Encrypt encrypts data for the public key.
func Encrypt(data []byte, to *Public) (encryptedSecret []byte, ciphertext []byte, err error) {
	scheme := to.KEM().Scheme()
	secretSeed, err := internal.RandRead(nil, scheme.EncapsulationSeedSize())
	if err != nil {
		return nil, nil, err
	}

	ciphScheme := scheme.Cipher()
	ciphertext = make([]byte, ciphScheme.NonceSize(), ciphScheme.NonceSize()+len(data)+ciphScheme.Overhead())
	_, err = io.ReadFull(rand.Reader, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, encryptedSecret = kem.Seal(to.KEM(), ciphertext, secretSeed, ciphertext, data)
	return
}

// Decrypt decrypts data for the private key.
func Decrypt(ciphertext []byte, encryptedSecret []byte, to *Private) (data []byte, err error) {
	ciphScheme := to.KEM().Scheme().Cipher()
	nonce := ciphScheme.NonceSize()
	data = make([]byte, 0, len(ciphertext)-nonce-ciphScheme.Overhead())
	return kem.Open(to.KEM(), data, encryptedSecret, ciphertext[:nonce], ciphertext[nonce:])
}
