package ae

import (
	"errors"
	"strings"
)

// Approach represents AE approach.
type Approach uint8

const (
	// InvalidApproach represents an invalid AE approach.
	InvalidApproach Approach = iota

	// EncryptThanMAC is an Encrypt-than-MAC approach.
	EncryptThanMAC

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

// ApproachFromString returns the AE approach from a string.
// Returns ErrInvalidApproach if the string is not a valid representation of an approach.
func ApproachFromString(str string) Approach {
	switch strings.ToUpper(str) {
	case "ETM":
		return EncryptThanMAC
	case "EAM":
		return EncryptAndMAC
	}
	return InvalidApproach
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
	return nil, ErrUnknownApproach
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
	ae.mac.Write(dst)
}

func decryptEtM(ae *baseAE, dst, src []byte) {
	ae.mac.Write(src)
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
	ae.mac.Write(src)
	ae.cipher.XORKeyStream(dst, src)
}

func decryptEaM(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.mac.Write(dst)
}
