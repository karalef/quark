package ae

import "errors"

// Approach represents AE approach.
type Approach uint8

const (
	// EncryptThanMAC is an Encrypt-than-MAC approach.
	EncryptThanMAC Approach = iota

	// EncryptAndMAC is an Encrypt-and-MAC approach.
	EncryptAndMAC
)

// String returns the string representation of the approach.
// If the value is not a valid approach it will be considered as EncryptThanMAC.
func (a Approach) String() string {
	switch a {
	default:
		return "EtM"
	case EncryptAndMAC:
		return "EaM"
	}
}

// FromString sets the approach from a string.
// Returns ErrInvalidApproach if the string is not a valid representation of an approach.
func (a Approach) FromString(str string) error {
	switch str {
	case "EtM":
		a = EncryptThanMAC
	case "EaM":
		a = EncryptAndMAC
	}
	return ErrUnknownApproach
}

// ErrUnknownApproach is returned if the approach is unknown.
var ErrUnknownApproach = errors.New("unknown authenticated encryption approach")

// NewEncrypter returns AE in encryption mode.
func (a Approach) NewEncrypter(s Scheme, sharedSecret []byte, iv []byte) (AE, error) {
	switch a {
	case EncryptThanMAC:
		return newEtM(s, sharedSecret, iv, encryptEtM)
	case EncryptAndMAC:
		return newEaM(s, sharedSecret, iv, encryptEaM)
	}
	return nil, ErrUnknownApproach
}

// NewDecrypter returns AE in decryption mode.
func (a Approach) NewDecrypter(s Scheme, sharedSecret []byte, iv []byte) (AE, error) {
	switch a {
	case EncryptThanMAC:
		return newEtM(s, sharedSecret, iv, decryptEtM)
	case EncryptAndMAC:
		return newEaM(s, sharedSecret, iv, decryptEaM)
	}
	panic("unknown approach")
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

func newEaM(s Scheme, sharedSecret, iv []byte, crypt func(*baseAE, []byte, []byte)) (AE, error) {
	key := make([]byte, s.Cipher().KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)
	return newAE(s, key, key, iv, crypt)
}

func encryptEaM(ae *baseAE, dst, src []byte) {
	ae.writeMAC(src)
	ae.cipher.XORKeyStream(dst, src)
}

func decryptEaM(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.writeMAC(dst)
}
