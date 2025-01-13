package encrypted

import (
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

func (c *Crypter) encryptData(dst, src, nonce, ad []byte) (Data, error) {
	ciph, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Data{}, err
	}
	ciph.Crypt(dst, src)
	return Data{
		Nonce: nonce,
		Data:  dst,
		Tag:   ciph.Tag(nil),
	}, nil
}

// EncryptDataBuf encrypts the data.
func (c *Crypter) EncryptDataBuf(data, nonce, ad []byte) (Data, error) {
	buf := make([]byte, len(data))
	return c.encryptData(buf, data, nonce, ad)
}

// EncryptData encrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) EncryptData(data, nonce, ad []byte) (Data, error) {
	return c.encryptData(data, data, nonce, ad)
}

// Decrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Decrypt(nonce, ad []byte) (aead.Cipher, error) {
	return c.scheme.Decrypt(c.key, nonce, ad)
}

func (c *Crypter) decryptData(dst []byte, data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.Nonce, ad)
	if err != nil {
		return nil, err
	}
	ciph.Crypt(dst, data.Data)
	if !mac.Equal(ciph.Tag(nil), data.Tag) {
		return nil, mac.ErrMismatch
	}
	return dst, nil
}

// DecryptDataBuf decrypts the data.
func (c *Crypter) DecryptDataBuf(data Data, ad []byte) ([]byte, error) {
	buf := make([]byte, len(data.Data))
	return c.decryptData(buf, data, ad)
}

// DecryptData decrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) DecryptData(data Data, ad []byte) ([]byte, error) {
	return c.decryptData(data.Data, data, ad)
}
