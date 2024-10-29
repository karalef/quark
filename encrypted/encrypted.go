package encrypted

import (
	"bytes"
	"errors"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/encrypted/secret"
)

// Data contains encrypted data.
type Data struct {
	Stream    `msgpack:",inline"`
	Data      []byte `msgpack:"data"`
	StreamTag `msgpack:",inline"`
}

// Stream preceeds the encrypted stream.
type Stream struct {
	Nonce []byte `msgpack:"nonce"`
}

// StreamTag contains the stream tag.
type StreamTag struct {
	Tag []byte `msgpack:"tag"`
}

// Verify verifies the stream tag.
func (t StreamTag) Verify(o StreamTag) error {
	if mac.Equal(t.Tag, o.Tag) {
		return nil
	}
	return mac.ErrMismatch
}

// NewSecret creates a new Symmetric with the given secret scheme.
func New(scheme *secret.Scheme) Symmetric {
	sec := NewSecret(scheme)
	return Symmetric{Secret: &sec}
}

// NewWithPassphrase creates a new Symmetric with the given password scheme.
func NewWithPassphrase(p PassphraseParams) Symmetric {
	pass := NewPassphrase(p)
	return Symmetric{Passphrase: &pass}
}

// Symmetric contains parameters for symmetric encryption based on key derivation.
type Symmetric struct {
	Passphrase *Passphrase `msgpack:"passphrase,omitempty"`
	Secret     *Secret     `msgpack:"secret,omitempty"`
}

// NewCrypter creates a new Crypter with the given shared secret.
func (s Symmetric) NewCrypter(sharedSecret []byte) (*Crypter, error) {
	return s.Secret.NewCrypter(sharedSecret)
}

// NewPassphraseCrypter creates a new Crypter with the given passphrase.
func (s Symmetric) NewPassphraseCrypter(passphrase string) (*Crypter, error) {
	return s.Passphrase.NewCrypter(passphrase)
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

// Encrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Encrypt(nonce, ad []byte) (Stream, aead.Cipher, error) {
	ciph, err := c.scheme.Encrypt(c.key, nonce, ad)
	return Stream{nonce}, ciph, err
}

// EncryptDataBuf encrypts the data.
func (c *Crypter) EncryptDataBuf(data, nonce, ad []byte) (Data, error) {
	stream, ciph, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Data{}, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(data)))

	//nolint:errcheck
	_, _ = aead.BufferedWriter{
		AEAD: ciph,
		W:    buf,
	}.Write(data)
	return Data{
		Stream:    stream,
		Data:      buf.Bytes(),
		StreamTag: StreamTag{Tag: ciph.Tag(nil)},
	}, nil
}

// EncryptData encrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) EncryptData(data, nonce, ad []byte) (Data, error) {
	stream, ciph, err := c.Encrypt(nonce, ad)
	if err != nil {
		return Data{}, err
	}
	ciph.Crypt(data, data)
	return Data{
		Stream:    stream,
		Data:      data,
		StreamTag: StreamTag{Tag: ciph.Tag(nil)},
	}, nil
}

// Decrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Decrypt(stream Stream, ad []byte) (aead.Cipher, error) {
	return c.scheme.Decrypt(c.key, stream.Nonce, ad)
}

// DecryptDataBuf decrypts the data.
func (c *Crypter) DecryptDataBuf(data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.Stream, ad)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(data.Data))

	//nolint:errcheck
	aead.Reader{
		AEAD: ciph,
		R:    bytes.NewReader(data.Data),
	}.Read(buf)

	return buf, StreamTag{Tag: ciph.Tag(nil)}.Verify(data.StreamTag)
}

// DecryptData decrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) DecryptData(data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.Stream, ad)
	if err != nil {
		return nil, err
	}
	ciph.Crypt(data.Data, data.Data)
	return data.Data, StreamTag{Tag: ciph.Tag(nil)}.Verify(data.StreamTag)
}

var ErrInvalidParameters = errors.New("invalid parameters")
