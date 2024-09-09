package single

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/encrypted"
)

// NewPassphrase creates a new Passphrase with the given scheme and passphrase.
func NewPassphrase(passphrase string, ad []byte, p encrypted.PassphraseParams) (Passphrase, aead.Cipher, error) {
	pass := encrypted.NewPassphrase(p)
	c, err := pass.NewCrypter(passphrase)
	if err != nil {
		return Passphrase{}, nil, err
	}
	stream, cipher, err := c.Encrypt(ad)
	if err != nil {
		return Passphrase{}, nil, err
	}
	return Passphrase{
		Passphrase: pass,
		Stream:     stream,
	}, cipher, nil
}

// Passphrase contains passphrase-based encryption parameters for the single data stream.
type Passphrase struct {
	encrypted.Passphrase
	encrypted.Stream
}

// Decrypt creates an authenticated cipher using passphrase.
func (p Passphrase) Decrypt(passphrase string, ad []byte) (aead.Cipher, error) {
	c, err := p.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(p.IV, ad)
}

// NewPassphraseData creates a new PassphraseData with the given scheme and passphrase.
func NewPassphraseData(passphrase string, data, ad []byte, p encrypted.PassphraseParams, buf ...bool) (PassphraseData, error) {
	pass := encrypted.NewPassphrase(p)
	c, err := pass.NewCrypter(passphrase)
	if err != nil {
		return PassphraseData{}, err
	}
	pd := PassphraseData{
		Passphrase: pass,
	}
	if len(buf) > 0 && buf[0] {
		pd.Data, err = c.EncryptDataBuf(data, ad)
	} else {
		pd.Data, err = c.EncryptData(data, ad)
	}
	if err != nil {
		return PassphraseData{}, err
	}
	return pd, nil
}

// PassphraseData contains passphrase-based encrypted data with parameters.
type PassphraseData struct {
	encrypted.Passphrase
	encrypted.Data
}

// Decrypt decrypts the data with the given passphrase.
func (p PassphraseData) Decrypt(passphrase string, ad []byte, buf ...bool) ([]byte, error) {
	c, err := p.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	if len(buf) > 0 && buf[0] {
		return c.DecryptDataBuf(p.Data, ad)
	}
	return c.DecryptData(p.Data, ad)
}
