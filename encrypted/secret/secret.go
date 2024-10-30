package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/scheme"
)

var _ scheme.Scheme = (*Scheme)(nil)

type Scheme struct {
	aead aead.Scheme
	xof  xof.Scheme
	name scheme.String
}

func (s *Scheme) Name() string      { return s.name.Name() }
func (s *Scheme) AEAD() aead.Scheme { return s.aead }
func (s *Scheme) XOF() xof.Scheme   { return s.xof }

func (s *Scheme) NonceSize() int { return s.aead.NonceSize() }
func (s *Scheme) TagSize() int   { return s.aead.TagSize() }

// Encrypter returns Cipher in encryption mode.
// Panics if nonce is not of length NonceSize().
func (s *Scheme) Encrypter(nonce, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.aead.Encrypt(s.DeriveKey(sharedSecret), nonce, associatedData)
}

// Decrypter returns Cipher in decryption mode.
// Panics if nonce is not of length NonceSize().
func (s *Scheme) Decrypter(nonce, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.aead.Decrypt(s.DeriveKey(sharedSecret), nonce, associatedData)
}

// DeriveKey returns key derived from shared secret.
//
//nolint:errcheck
func (s *Scheme) DeriveKey(sharedSecret []byte) []byte {
	key := make([]byte, s.aead.KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)
	return key
}

// Build creates a password-based authenticated encryption scheme from AEAD and XOF schemes.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, xof xof.Scheme) *Scheme {
	if aead == nil || xof == nil {
		panic("secret.Build: nil scheme part")
	}
	return &Scheme{
		name: scheme.String(scheme.Join(aead, xof)),
		aead: aead,
		xof:  xof,
	}
}

// FromName creates a secret scheme from its name.
func FromName(schemeName string) (*Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1])
}

// FromNames creates a secret scheme from AEAD and XOF scheme names.
func FromNames(aeadName, xofName string) (*Scheme, error) {
	xof, err := xof.ByName(xofName)
	if err != nil {
		return nil, err
	}
	aead, err := aead.ByName(aeadName)
	if err != nil {
		return nil, err
	}
	return Build(aead, xof), nil
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
