package aead

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/scheme"
)

// Scheme represents an AEAD scheme.
type Scheme interface {
	scheme.Scheme
	Cipher() cipher.Scheme
	MAC() mac.Scheme

	// Encrypter returns Cipher in de/encryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Crypter(iv, key, macKey, associatedData []byte, decrypt bool) (Cipher, error)
}

// Build creates an AEAD scheme.
// Panics if one of the arguments is nil.
func Build(cipher cipher.Scheme, mac mac.Scheme) Scheme {
	if cipher == nil || mac == nil {
		panic("nil scheme part")
	}
	return &baseScheme{
		StringName: scheme.StringName(scheme.Join(cipher, mac)),
		cipher:     cipher,
		mac:        mac,
	}
}

// FromName creates an AEAD scheme from its name.
func FromName(schemeName string) (Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1])
}

// FromNames creates an AEAD scheme from its part names.
func FromNames(cipherName, macName string) (Scheme, error) {
	cipher, err := cipher.ByName(cipherName)
	if err != nil {
		return nil, err
	}
	mac, err := mac.ByName(macName)
	if err != nil {
		return nil, err
	}
	return Build(cipher, mac), nil
}

var _ Scheme = (*baseScheme)(nil)

type baseScheme struct {
	scheme.StringName
	cipher cipher.Scheme
	mac    mac.Scheme
}

func (s *baseScheme) Cipher() cipher.Scheme { return s.cipher }
func (s *baseScheme) MAC() mac.Scheme       { return s.mac }

func (s *baseScheme) Crypter(iv, key, macKey, associatedData []byte, decrypt bool) (Cipher, error) {
	return New(s, iv, key, macKey, associatedData, decrypt)
}
