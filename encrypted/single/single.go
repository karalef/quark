package single

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/secret"
)

// NewData creates a new Data with the given scheme and shared secret.
func NewData(scheme *secret.Scheme, sharedSecret, data, nonce, ad []byte, buf ...bool) (Data, error) {
	sym := encrypted.New(scheme)
	c, err := sym.NewCrypter(sharedSecret)
	if err != nil {
		return Data{}, err
	}
	d := Data{
		Symmetric: sym,
	}
	if len(buf) > 0 && buf[0] {
		d.Data, err = c.EncryptDataBuf(data, nonce, ad)
	} else {
		d.Data, err = c.EncryptData(data, nonce, ad)
	}
	if err != nil {
		return Data{}, err
	}
	return d, nil
}

// NewDataWithPassphrase creates a new Data with the given scheme and shared secret.
func NewDataWithPassphrase(passphrase string, data, nonce, ad []byte, p encrypted.PassphraseParams, buf ...bool) (Data, error) {
	sym := encrypted.NewWithPassphrase(p)
	c, err := sym.NewPassphraseCrypter(passphrase)
	if err != nil {
		return Data{}, err
	}
	d := Data{
		Symmetric: sym,
	}
	if len(buf) > 0 && buf[0] {
		d.Data, err = c.EncryptDataBuf(data, nonce, ad)
	} else {
		d.Data, err = c.EncryptData(data, nonce, ad)
	}
	if err != nil {
		return Data{}, err
	}
	return d, nil
}

// Data contains encryption parameters with a single non-streamed data.
type Data struct {
	encrypted.Symmetric
	encrypted.Data
}

// Decrypt decrypts the data with the given shared secret.
func (s Data) Decrypt(sharedSecret, ad []byte, buf ...bool) ([]byte, error) {
	crypter, err := s.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	if len(buf) > 0 && buf[0] {
		return crypter.DecryptDataBuf(s.Data, ad)
	}
	return crypter.DecryptData(s.Data, ad)
}

// DecryptPassphrase decrypts the data with the given passphrase.
func (s Data) DecryptPassphrase(passphrase string, ad []byte, buf ...bool) ([]byte, error) {
	crypter, err := s.NewPassphraseCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	if len(buf) > 0 && buf[0] {
		return crypter.DecryptDataBuf(s.Data, ad)
	}
	return crypter.DecryptData(s.Data, ad)
}

// New creates a new Stream with the given scheme and shared secret.
func New(scheme *secret.Scheme, sharedSecret, nonce, ad []byte) (Stream, aead.Cipher, error) {
	sym := encrypted.New(scheme)
	c, err := sym.NewCrypter(sharedSecret)
	if err != nil {
		return Stream{}, nil, err
	}
	stream, cipher, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Stream{}, nil, err
	}
	return Stream{
		Symmetric: sym,
		Stream:    stream,
	}, cipher, nil
}

// NewWithPassphrase creates a new Stream with the given scheme and passphrase.
func NewWithPassphrase(passphrase string, nonce, ad []byte, p encrypted.PassphraseParams) (Stream, aead.Cipher, error) {
	sym := encrypted.NewWithPassphrase(p)
	c, err := sym.NewPassphraseCrypter(passphrase)
	if err != nil {
		return Stream{}, nil, err
	}
	stream, cipher, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Stream{}, nil, err
	}
	return Stream{
		Symmetric: sym,
		Stream:    stream,
	}, cipher, nil
}

// Stream contain encryption parameters for the single data stream.
type Stream struct {
	encrypted.Symmetric
	encrypted.Stream
}

// Decrypt creates an authenticated cipher using shared secret.
func (s Stream) Decrypt(sharedSecret, ad []byte) (aead.Cipher, error) {
	c, err := s.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(s.Stream.Nonce, ad)
}

// DecryptPassphrase creates an authenticated cipher using passphrase.
func (s Stream) DecryptPassphrase(passphrase string, ad []byte) (aead.Cipher, error) {
	c, err := s.NewPassphraseCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(s.Stream.Nonce, ad)
}
