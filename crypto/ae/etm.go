package ae

// NewEtMEncrypter returns AE in encryption mode with the Encrypt-than-MAC approach.
func NewEtMEncrypter(s Scheme, sharedSecret, iv []byte) (AE, error) {
	return newEtM(s, sharedSecret, iv, encryptEtM)
}

// NewEtMDecrypter returns AE in decryption mode with the Encrypt-than-MAC approach.
func NewEtMDecrypter(s Scheme, sharedSecret, iv []byte) (AE, error) {
	return newEtM(s, sharedSecret, iv, decryptEtM)
}

func newEtM(s Scheme, sharedSecret, iv []byte, crypt func(*baseAE, []byte, []byte)) (AE, error) {
	cipherKey := make([]byte, s.Cipher().KeySize())
	macKey := make([]byte, s.MAC().KeySize())

	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(cipherKey)
	xof.Read(macKey)

	return newAE(s, cipherKey, macKey, iv, crypt)
}

func encryptEtM(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.writeMAC(dst)
}

func decryptEtM(ae *baseAE, dst, src []byte) {
	ae.writeMAC(src)
	ae.cipher.XORKeyStream(dst, src)
}
