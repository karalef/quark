package encrypted

import (
	"errors"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/mac"
)

// Data contains encrypted data.
type Data struct {
	Nonce []byte `msgpack:"nonce"`
	Data  []byte `msgpack:"data"`
	Tag   []byte `msgpack:"tag"`
}

// NewCrypter creates a new AEAD crypter.
func NewCrypter(scheme aead.Scheme, key []byte) (*Crypter, error) {
	return &Crypter{
		scheme: scheme,
		key:    key,
	}, nil
}

// Crypter encrypts and decrypts data using AEAD scheme.
type Crypter struct {
	scheme aead.Scheme
	key    []byte
}

// NonceSize returns the nonce size for the AEAD scheme.
func (c *Crypter) NonceSize() int { return c.scheme.NonceSize() }

// Encrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Encrypt(nonce, ad []byte) (aead.Cipher, error) {
	return c.scheme.Encrypt(c.key, nonce, ad)
}

// EncryptDataBuf encrypts the data.
func (c *Crypter) EncryptDataBuf(data, nonce, ad []byte) (Data, error) {
	ciph, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Data{}, err
	}
	buf := make([]byte, len(data))
	ciph.Crypt(buf, data)

	return Data{
		Nonce: nonce,
		Data:  buf,
		Tag:   ciph.Tag(nil),
	}, nil
}

// EncryptData encrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) EncryptData(data, nonce, ad []byte) (Data, error) {
	ciph, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Data{}, err
	}
	ciph.Crypt(data, data)
	return Data{
		Nonce: nonce,
		Data:  data,
		Tag:   ciph.Tag(nil),
	}, nil
}

// Decrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Decrypt(nonce, ad []byte) (aead.Cipher, error) {
	return c.scheme.Decrypt(c.key, nonce, ad)
}

// DecryptDataBuf decrypts the data.
func (c *Crypter) DecryptDataBuf(data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.Nonce, ad)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(data.Data))
	ciph.Crypt(buf, data.Data)

	return buf, verifyTag(ciph, data.Tag)
}

// DecryptData decrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) DecryptData(data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.Nonce, ad)
	if err != nil {
		return nil, err
	}
	ciph.Crypt(data.Data, data.Data)
	return data.Data, verifyTag(ciph, data.Tag)
}

func verifyTag(c aead.Cipher, tag []byte) error {
	if !mac.Equal(c.Tag(nil), tag) {
		return mac.ErrMismatch
	}
	return nil
}

var ErrInvalidParameters = errors.New("invalid parameters")
