package encrypted

import (
	"bytes"
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/secret"
)

// Data contains encrypted data.
type Data struct {
	Stream
	Data []byte `msgpack:"data"`
	StreamTag
}

// Stream preceeds the encrypted stream.
type Stream struct {
	IV []byte `msgpack:"iv"`
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
func New(scheme secret.Scheme) Symmetric {
	sec := NewSecret(scheme)
	return Symmetric{
		Secret: &sec.Secret,
		Scheme: sec.Scheme,
	}
}

// NewWithPassphrase creates a new Symmetric with the given password scheme.
func NewWithPassphrase(p PassphraseParams) Symmetric {
	pass := NewPassphrase(p)
	return Symmetric{
		Passphrase: &pass.Passphrase,
		Scheme:     pass.Scheme,
	}
}

// Symmetric contains parameters for symmetric encryption based on key derivation.
type Symmetric struct {
	Passphrase *PassphraseHeader `msgpack:"passphrase,omitempty"`
	Secret     *SecretHeader     `msgpack:"secret,omitempty"`

	Scheme Scheme `msgpack:"scheme"`
}

// NewCrypter creates a new Crypter with the given shared secret.
func (s Symmetric) NewCrypter(sharedSecret []byte) (*Crypter, error) {
	return Secret{
		Secret: *s.Secret,
		Scheme: s.Scheme,
	}.NewCrypter(sharedSecret)
}

// NewPassphraseCrypter creates a new Crypter with the given passphrase.
func (s Symmetric) NewPassphraseCrypter(passphrase string) (*Crypter, error) {
	return Passphrase{
		Passphrase: *s.Passphrase,
		Scheme:     s.Scheme,
	}.NewCrypter(passphrase)
}

// NewCrypter creates a new AEAD crypter.
func NewCrypter(scheme aead.Scheme, cipherKey, macKey []byte) (*Crypter, error) {
	if len(cipherKey) != scheme.Cipher().KeySize() {
		return nil, cipher.ErrKeySize
	}
	if err := mac.CheckKeySize(scheme.MAC(), len(macKey)); err != nil {
		return nil, err
	}
	return &Crypter{
		scheme:    scheme,
		cipherKey: cipherKey,
		macKey:    macKey,
	}, nil
}

// Crypter encrypts and decrypts data using AEAD scheme.
type Crypter struct {
	scheme            aead.Scheme
	cipherKey, macKey []byte
}

// Encrypt generates the iv and creates a new AEAD cipher with associated data.
func (c *Crypter) Encrypt(ad []byte) (Stream, aead.Cipher, error) {
	iv := crypto.Rand(c.scheme.Cipher().IVSize())
	ciph, err := c.scheme.Crypter(iv, c.cipherKey, c.macKey, ad, false)
	return Stream{iv}, ciph, err
}

// EncryptDataBuf generates the iv and encrypts the data.
// It has internal buffering so the provided data will not be modified.
func (c *Crypter) EncryptDataBuf(data, ad []byte) (Data, error) {
	iv, ciph, err := c.Encrypt(ad)
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
		Stream:    iv,
		Data:      buf.Bytes(),
		StreamTag: StreamTag{Tag: ciph.Tag(nil)},
	}, nil
}

// EncryptData generates the iv and encrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c *Crypter) EncryptData(data, ad []byte) (Data, error) {
	iv, ciph, err := c.Encrypt(ad)
	if err != nil {
		return Data{}, err
	}
	ciph.Crypt(data, data)
	return Data{
		Stream:    iv,
		Data:      data,
		StreamTag: StreamTag{Tag: ciph.Tag(nil)},
	}, nil
}

// Decrypt creates a new AEAD cipher with associated data.
func (c *Crypter) Decrypt(iv, ad []byte) (aead.Cipher, error) {
	return c.scheme.Crypter(iv, c.cipherKey, c.macKey, ad, true)
}

// DecryptDataBuf decrypts the data.
// It has internal buffering so the provided data will not be modified.
func (c *Crypter) DecryptDataBuf(data Data, ad []byte) ([]byte, error) {
	ciph, err := c.Decrypt(data.IV, ad)
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
	ciph, err := c.Decrypt(data.IV, ad)
	if err != nil {
		return nil, err
	}
	ciph.Crypt(data.Data, data.Data)
	return data.Data, StreamTag{Tag: ciph.Tag(nil)}.Verify(data.StreamTag)
}

var (
	ErrInvalidParameters = errors.New("invalid parameters")
	ErrInvalidScheme     = errors.New("invalid symmetric encryption scheme")
)
