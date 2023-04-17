package quark

import (
	"crypto/rand"
	"io"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
)

// Encrypt encrypts data for the public key.
func Encrypt(data []byte, to PublicKeyset) (encryptedSecret []byte, ciphertext []byte, err error) {
	scheme := to.KEMPublicKey().Scheme()
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

	ciphertext, encryptedSecret = kem.Seal(to.KEMPublicKey(), ciphertext, secretSeed, ciphertext, data)
	return
}

// Decrypt decrypts data for the private key.
func Decrypt(ciphertext []byte, encryptedSecret []byte, to PrivateKeyset) (data []byte, err error) {
	ciphScheme := to.KEMPublicKey().Scheme().Cipher()
	nonce := ciphScheme.NonceSize()
	data = make([]byte, 0, len(ciphertext)-nonce-ciphScheme.Overhead())
	return kem.Open(to.KEMPrivateKey(), data, encryptedSecret, ciphertext[:nonce], ciphertext[nonce:])
}

// Sign hashes and signs the message.
func Sign(msg []byte, with PrivateKeyset) ([]byte, error) {
	return with.SignPrivateKey().Sign(with.Hash().Sum(msg))
}

// Verify calculates the message hash and verifies the signature.
func Verify(msg []byte, signature []byte, with PublicKeyset) (bool, error) {
	return with.SignPublicKey().Verify(with.Hash().Sum(msg), signature)
}
