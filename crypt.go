package quark

import (
	cryptorand "crypto/rand"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
)

// Encrypt encrypts data for the public key and appends the result to dst, returning the updated slice.
// The result also includes the nonce (nonce, ciphertext, tag).
func Encrypt(dst, data []byte, to Public) (encryptedSecret []byte, ciphertext []byte, err error) {
	nonceSize := to.KEM().Scheme().Cipher().NonceSize()
	tagSize := to.KEM().Scheme().Cipher().Overhead()

	ciphertextSize := nonceSize + len(data) + tagSize
	if cap(dst)-len(dst) < ciphertextSize {
		dst = make([]byte, 0, ciphertextSize)
	}

	ciphertext = dst[nonceSize:]
	nonce := dst[:nonceSize]
	if _, err = cryptorand.Read(nonce); err != nil {
		return nil, nil, err
	}

	secretSeed := internal.Rand(to.KEM().Scheme().EncapsulationSeedSize())
	ciphertext, encryptedSecret = kem.Seal(to.KEM(), ciphertext, secretSeed, nonce, data)
	ciphertext = dst
	return
}

// Decrypt decrypts data for the private key and appends the result to dst, returning the updated slice.
// dst can be ciphertext[:0] to reuse the storage of ciphertext.
func Decrypt(dst, ciphertext []byte, encryptedSecret []byte, to Private) ([]byte, error) {
	nonceSize := to.KEM().Scheme().Cipher().NonceSize()

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	return kem.Open(to.KEM(), dst, encryptedSecret, nonce, ciphertext)
}
