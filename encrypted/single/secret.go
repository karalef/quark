package single

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/secret"
	"github.com/karalef/quark/encrypted"
)

// NewSecret creates a new Secret with the given scheme and shared secret.
func NewSecret(scheme secret.Scheme, sharedSecret, ad []byte) (Secret, aead.Cipher, error) {
	sec := encrypted.NewSecret(scheme)
	c, err := sec.NewCrypter(sharedSecret)
	if err != nil {
		return Secret{}, nil, err
	}
	stream, cipher, err := c.Encrypt(ad)
	if err != nil {
		return Secret{}, nil, err
	}
	return Secret{
		Secret: sec,
		Stream: stream,
	}, cipher, nil
}

// Secret contains shared secret based encryption parameters for the single data stream.
type Secret struct {
	encrypted.Secret
	encrypted.Stream
}

// Decrypt creates an authenticated cipher using shared secret.
func (s Secret) Decrypt(sharedSecret, ad []byte) (aead.Cipher, error) {
	c, err := s.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(s.Stream.IV, ad)
}

// NewSecretData creates a new SymmetricData with the given scheme and shared secret.
func NewSecretData(scheme secret.Scheme, sharedSecret, data, ad []byte, buf ...bool) (SecretData, error) {
	s := encrypted.NewSecret(scheme)
	c, err := s.NewCrypter(sharedSecret)
	if err != nil {
		return SecretData{}, err
	}
	sd := SecretData{
		Secret: s,
	}
	if len(buf) > 0 && buf[0] {
		sd.Data, err = c.EncryptDataBuf(data, ad)
	} else {
		sd.Data, err = c.EncryptData(data, ad)
	}
	if err != nil {
		return SecretData{}, err
	}
	return sd, nil
}

// SecretData contains shared secret based encrypted data with parameters.
type SecretData struct {
	encrypted.Secret
	encrypted.Data
}

// Decrypt decrypts the data with the given shared secret.
func (s SecretData) Decrypt(sharedSecret, ad []byte, buf ...bool) ([]byte, error) {
	crypter, err := s.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	if len(buf) > 0 && buf[0] {
		return crypter.DecryptDataBuf(s.Data, ad)
	}
	return crypter.DecryptData(s.Data, ad)
}
