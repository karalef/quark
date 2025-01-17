package encrypted

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack/binary"
	"github.com/karalef/quark/scheme"
)

var _ scheme.Scheme = Secret{}

// Secret is a shared secret-based authenticated encryption scheme.
type Secret struct {
	aead aead.Scheme
	xof  xof.Scheme
	name scheme.String
}

func (s Secret) Name() string      { return s.name.Name() }
func (s Secret) AEAD() aead.Scheme { return s.aead }
func (s Secret) XOF() xof.Scheme   { return s.xof }

func (s Secret) NonceSize() int { return s.aead.NonceSize() }
func (s Secret) TagSize() int   { return s.aead.TagSize() }

// Encrypter returns Cipher in encryption mode.
// Panics if nonce is not of length NonceSize().
func (s Secret) Encrypter(nonce, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.aead.Encrypt(s.DeriveKey(sharedSecret), nonce, associatedData)
}

// Decrypter returns Cipher in decryption mode.
// Panics if nonce is not of length NonceSize().
func (s Secret) Decrypter(nonce, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.aead.Decrypt(s.DeriveKey(sharedSecret), nonce, associatedData)
}

// Crypter creates a new Crypter with the given shared secret.
func (s Secret) Crypter(sharedSecret []byte) (*Crypter, error) {
	return NewCrypter(s.aead, s.DeriveKey(sharedSecret))
}

// DeriveKey returns key derived from shared secret.
//
//nolint:errcheck
func (s Secret) DeriveKey(sharedSecret []byte) []byte {
	key := make([]byte, s.aead.KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)
	return key
}

// BuildSecret creates a shared secret-based authenticated encryption scheme from AEAD and XOF schemes.
// Panics if one of the arguments is nil.
func BuildSecret(aead aead.Scheme, xof xof.Scheme) Secret {
	if aead == nil || xof == nil {
		panic("encrypted.BuildSecret: nil scheme part")
	}
	return Secret{
		name: scheme.String(scheme.Join(aead, xof)),
		aead: aead,
		xof:  xof,
	}
}

// SecretFromName creates a shared secret-based authenticated encryption scheme from its name.
func SecretFromName(schemeName string) (Secret, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return Secret{}, err
	}
	return SecretFromNames(parts[0], parts[1])
}

// SecretFromNames creates a shared secret-based authenticated encryption scheme from AEAD and XOF scheme names.
func SecretFromNames(aeadName, xofName string) (Secret, error) {
	xof, err := xof.ByName(xofName)
	if err != nil {
		return Secret{}, err
	}
	aead, err := aead.ByName(aeadName)
	if err != nil {
		return Secret{}, err
	}
	return BuildSecret(aead, xof), nil
}

var (
	_ binary.CustomEncoder = Secret{}
	_ binary.CustomDecoder = (*Secret)(nil)
)

// EncodeMsgpack implements binary.CustomEncoder.
func (s Secret) EncodeMsgpack(enc *binary.Encoder) error {
	return enc.EncodeString(s.Name())
}

// DecodeMsgpack implements binary.CustomDecoder.
func (s *Secret) DecodeMsgpack(dec *binary.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	sch, err := SecretFromName(str)
	if err != nil {
		return err
	}
	*s = sch
	return nil
}
