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

	// EncryptThenMAC is an Encrypt-then-MAC approach.
	EncryptThenMAC

	// EncryptAndMAC is an Encrypt-and-MAC approach.
	EncryptAndMAC
)

// String returns the string representation of the approach.
// If the value is not a valid approach it will be considered as EncryptThenMAC.
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
		return EncryptThenMAC
	case "EAM":
		return EncryptAndMAC
	}
	return InvalidApproach
}

// ErrUnknownApproach is returned if the approach is unknown.
var ErrUnknownApproach = errors.New("unknown authenticated encryption approach")

// NewEncrypter returns AE in encryption mode.
func NewEncrypter(s Scheme, sharedSecret []byte, iv []byte) (AE, error) {
	switch s.Approach() {
	case EncryptThenMAC:
		return newEtM(s, sharedSecret, iv, false)
	case EncryptAndMAC:
		return newEaM(s, sharedSecret, iv, false)
	}
	return nil, ErrUnknownApproach
}

// NewDecrypter returns AE in decryption mode.
func NewDecrypter(s Scheme, sharedSecret []byte, iv []byte) (AE, error) {
	switch s.Approach() {
	case EncryptThenMAC:
		return newEtM(s, sharedSecret, iv, true)
	case EncryptAndMAC:
		return newEaM(s, sharedSecret, iv, true)
	}
	return nil, ErrUnknownApproach
}

func newEtM(s Scheme, sharedSecret, iv []byte, decrypt bool) (AE, error) {
	cipherKey := make([]byte, s.Cipher().KeySize())
	macKey := make([]byte, s.MAC().KeySize())

	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(cipherKey)
	xof.Read(macKey)

	if decrypt {
		return newAE(s, cipherKey, macKey, iv, macThenCrypt)
	}
	return newAE(s, cipherKey, macKey, iv, cryptThenMac)
}

func newEaM(s Scheme, sharedSecret, iv []byte, decrypt bool) (AE, error) {
	key := make([]byte, s.Cipher().KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)

	if decrypt {
		return newAE(s, key, key, iv, cryptThenMac)
	}
	return newAE(s, key, key, iv, macThenCrypt)
}

func cryptThenMac(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.mac.Write(dst)
}

func macThenCrypt(ae *baseAE, dst, src []byte) {
	ae.mac.Write(src)
	ae.cipher.XORKeyStream(dst, src)
}
