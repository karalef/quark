package ae

// NewEandMEncrypter returns AE in encryption mode with the Encrypt-and-MAC approach.
func NewEandMEncrypter(s Scheme, sharedSecret, iv []byte) (AE, error) {
	return newEandM(s, sharedSecret, iv, encryptEandM)
}

// NewEandMDecrypter returns AE in encryption mode with the Encrypt-and-MAC approach.
func NewEandMDecrypter(s Scheme, sharedSecret, iv []byte) (AE, error) {
	return newEandM(s, sharedSecret, iv, decryptEandM)
}

func newEandM(s Scheme, sharedSecret, iv []byte, crypt func(*baseAE, []byte, []byte)) (AE, error) {
	key := make([]byte, s.Cipher().KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)
	return newAE(s, key, key, iv, crypt)
}

func encryptEandM(ae *baseAE, dst, src []byte) {
	ae.writeMAC(src)
	ae.cipher.XORKeyStream(dst, src)
}

func decryptEandM(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.writeMAC(dst)
}
