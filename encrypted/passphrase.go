package encrypted

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/pack/binary"
	"github.com/karalef/quark/scheme"
)

var _ scheme.Scheme = Passphrase{}

// Passphrase represents passphrase-based authenticated encryption scheme.
type Passphrase struct {
	aead aead.Scheme
	kdf  kdf.Scheme
	name scheme.String
}

// Name returns scheme name.
func (p Passphrase) Name() string      { return p.name.Name() }
func (p Passphrase) AEAD() aead.Scheme { return p.aead }
func (p Passphrase) KDF() kdf.Scheme   { return p.kdf }
func (p Passphrase) NonceSize() int    { return p.aead.NonceSize() }
func (p Passphrase) TagSize() int      { return p.aead.TagSize() }

// Encrypter returns Cipher in encryption mode.
// Panics if nonce is not of length NonceSize().
func (p Passphrase) Encrypter(passphrase string, nonce, salt, ad []byte, cost kdf.Cost) (aead.Cipher, error) {
	key, err := p.DeriveKey(passphrase, salt, cost)
	if err != nil {
		return nil, err
	}
	return p.aead.Encrypt(key, nonce, ad)
}

// Decrypter returns Cipher in decryption mode.
// Panics if nonce is not of length NonceSize().
func (p Passphrase) Decrypter(passphrase string, nonce, salt, ad []byte, cost kdf.Cost) (aead.Cipher, error) {
	key, err := p.DeriveKey(passphrase, salt, cost)
	if err != nil {
		return nil, err
	}
	return p.aead.Decrypt(key, nonce, ad)
}

// Crypter creates a new Crypter with the given passphrase.
func (p Passphrase) Crypter(passphrase string, salt []byte, cost kdf.Cost) (*Crypter, error) {
	key, err := p.DeriveKey(passphrase, salt, cost)
	if err != nil {
		return nil, err
	}
	return NewCrypter(p.aead, key)
}

// DeriveKey returns key derived from passphrase.
func (p Passphrase) DeriveKey(passphrase string, salt []byte, cost kdf.Cost) ([]byte, error) {
	return kdf.Derive(p.kdf, cost, passphrase, salt, p.aead.KeySize())
}

// BuildPassphrase creates a passphrase-based authenticated encryption scheme from AEAD and KDF schemes.
// Panics if one of the arguments is nil.
func BuildPassphrase(aead aead.Scheme, kdf kdf.Scheme) Passphrase {
	if aead == nil || kdf == nil {
		panic("encrypted.BuildPassphrase: nil scheme part")
	}
	return Passphrase{
		name: scheme.String(scheme.Join(aead, kdf)),
		aead: aead,
		kdf:  kdf,
	}
}

// PassphraseFromName creates a passphrase-based authenticated encryption scheme from its name.
func PassphraseFromName(schemeName string) (Passphrase, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return Passphrase{}, err
	}
	return PassphraseFromNames(parts[0], parts[1])
}

// PassphraseFromNames creates a passphrase-based authenticated encryption scheme from AEAD and KDF scheme names.
func PassphraseFromNames(aeadName, kdfName string) (Passphrase, error) {
	kdf, err := kdf.ByName(kdfName)
	if err != nil {
		return Passphrase{}, err
	}
	aead, err := aead.ByName(aeadName)
	if err != nil {
		return Passphrase{}, err
	}
	return BuildPassphrase(aead, kdf), nil
}

var (
	_ binary.CustomEncoder = Passphrase{}
	_ binary.CustomDecoder = (*Passphrase)(nil)
)

// EncodeMsgpack implements binary.CustomEncoder.
func (p Passphrase) EncodeMsgpack(enc *binary.Encoder) error {
	return enc.EncodeString(p.Name())
}

// DecodeMsgpack implements binary.CustomDecoder.
func (p *Passphrase) DecodeMsgpack(dec *binary.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	sch, err := PassphraseFromName(str)
	if err != nil {
		return err
	}
	*p = sch
	return nil
}
