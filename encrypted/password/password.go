// Package password provides password-based authenticated encryption.
package password

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/scheme"
)

var _ scheme.Scheme = (*Scheme)(nil)

// Scheme represents password-based authenticated encryption scheme.
type Scheme struct {
	aead aead.Scheme
	kdf  kdf.Scheme
	name scheme.StringName
}

// Name returns scheme name.
func (s *Scheme) Name() string      { return s.name.Name() }
func (s *Scheme) AEAD() aead.Scheme { return s.aead }
func (s *Scheme) KDF() kdf.Scheme   { return s.kdf }
func (s *Scheme) NonceSize() int    { return s.aead.NonceSize() }
func (s *Scheme) TagSize() int      { return s.aead.TagSize() }

// Encrypter returns Cipher in encryption mode.
// Panics if nonce is not of length NonceSize().
func (s *Scheme) Encrypter(password string, nonce, salt, ad []byte, cost kdf.Cost) (aead.Cipher, error) {
	key, err := s.DeriveKey(password, salt, cost)
	if err != nil {
		return nil, err
	}
	return s.aead.Encrypt(key, nonce, ad)
}

// Decrypter returns Cipher in decryption mode.
// Panics if nonce is not of length NonceSize().
func (s *Scheme) Decrypter(password string, nonce, salt, ad []byte, cost kdf.Cost) (aead.Cipher, error) {
	key, err := s.DeriveKey(password, salt, cost)
	if err != nil {
		return nil, err
	}
	return s.aead.Decrypt(key, nonce, ad)
}

// DeriveKey returns key derived from password.
func (s *Scheme) DeriveKey(password string, salt []byte, cost kdf.Cost) ([]byte, error) {
	return kdf.Derive(s.KDF(), cost, password, salt, s.AEAD().KeySize())
}

// Build creates a password-based authenticated encryption scheme from AEAD and KDF schemes.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, kdf kdf.Scheme) *Scheme {
	if aead == nil || kdf == nil {
		panic("password.Build: nil scheme part")
	}
	return &Scheme{
		name: scheme.StringName(scheme.Join(aead, kdf)),
		aead: aead,
		kdf:  kdf,
	}
}

// FromName creates a password scheme from its name.
func FromName(schemeName string) (*Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1])
}

// FromNames creates a password scheme from AEAD and KDF scheme names.
func FromNames(aeadName, kdfName string) (*Scheme, error) {
	kdf, err := kdf.ByName(kdfName)
	if err != nil {
		return nil, err
	}
	aead, err := aead.ByName(aeadName)
	if err != nil {
		return nil, err
	}
	return Build(aead, kdf), nil
}

var (
	_ pack.CustomEncoder = (*Scheme)(nil)
	_ pack.CustomDecoder = (*Scheme)(nil)
)

// EncodeMsgpack implements pack.CustomEncoder.
func (s *Scheme) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.Name())
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *Scheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	sch, err := FromName(str)
	if err != nil {
		return err
	}
	*s = *sch
	return nil
}
