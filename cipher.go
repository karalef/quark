package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
)

// NewMaster returns a new master key.
func NewMaster(scheme aead.Scheme, kdf kdf.Expander) Master {
	return Master{
		KDF:    kdf,
		Scheme: scheme,
	}
}

// Master is a key used to derive a cipher keys.
type Master struct {
	KDF    kdf.Expander
	Scheme aead.Scheme
}

// Derive derives a key with the given info.
func (mk Master) Derive(info []byte) []byte {
	return mk.KDF.Expand(info, uint(mk.Scheme.KeySize()))
}

// New derives a cipher key with the given info.
func (mk Master) New(info []byte) (Cipher, error) {
	return NewCipher(mk.Scheme, mk.Derive(info))
}

// Encrypter returns a new encrypter using the key derived with info.
func (mk Master) Encrypter(info []byte, s NonceSource) (Encrypter, error) {
	k, err := mk.New(info)
	if err != nil {
		return Encrypter{}, err
	}
	return NewEncrypter(k, s), nil
}

// Data contains encrypted data.
type Data struct {
	_msgpack struct{} `msgpack:",as_array"`

	Nonce []byte
	Data  []byte
	Tag   []byte
}

// NewCipher creates a new Cipher.
func NewCipher(scheme aead.Scheme, key []byte) (Cipher, error) {
	if len(key) != scheme.KeySize() {
		return Cipher{}, aead.ErrKeySize
	}
	return Cipher{scheme: scheme, key: key}, nil
}

// Cipher contains a symmetric cipher key with scheme.
type Cipher struct {
	scheme aead.Scheme
	key    []byte
}

// NonceSize returns the nonce size for the AEAD scheme.
func (c Cipher) NonceSize() int { return c.scheme.NonceSize() }

// Encrypt creates a new AEAD cipher with associated data.
func (c Cipher) Encrypt(nonce, ad []byte) aead.Cipher {
	return c.scheme.Encrypt(c.key, nonce, ad)
}

func (c Cipher) encryptData(dst, src, nonce, ad []byte) Data {
	ciph := c.Encrypt(nonce, ad)
	ciph.Crypt(dst, src)
	return Data{
		Nonce: nonce,
		Data:  dst,
		Tag:   ciph.Tag(nil),
	}
}

// EncryptDataBuf encrypts the data.
func (c Cipher) EncryptDataBuf(data, nonce, ad []byte) Data {
	buf := make([]byte, len(data))
	return c.encryptData(buf, data, nonce, ad)
}

// EncryptData encrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c Cipher) EncryptData(data, nonce, ad []byte) Data {
	return c.encryptData(data, data, nonce, ad)
}

// Decrypt creates a new AEAD cipher with associated data.
func (c Cipher) Decrypt(nonce, ad []byte) aead.Cipher {
	return c.scheme.Decrypt(c.key, nonce, ad)
}

func (c Cipher) decryptData(dst []byte, data Data, ad []byte) ([]byte, error) {
	ciph := c.Decrypt(data.Nonce, ad)
	ciph.Crypt(dst, data.Data)
	if err := aead.Verify(ciph, data.Tag); err != nil {
		return nil, err
	}
	return dst, nil
}

// DecryptDataBuf decrypts the data.
func (c Cipher) DecryptDataBuf(data Data, ad []byte) ([]byte, error) {
	buf := make([]byte, len(data.Data))
	return c.decryptData(buf, data, ad)
}

// DecryptData decrypts the data.
// It has no internal buffering so the provided data will be modified.
func (c Cipher) DecryptData(data Data, ad []byte) ([]byte, error) {
	return c.decryptData(data.Data, data, ad)
}

// NewEncrypter returns a new encrypter from the given key and nonce source.
// If the nonce source is nil, LFSRNonce is used.
func NewEncrypter(key Cipher, source NonceSource) Encrypter {
	if source == nil {
		source = NewLFSR(key.NonceSize(), 0)
	}
	return Encrypter{
		key:    key,
		source: source,
	}
}

// Encrypter encrypts multiple data using nonce source.
type Encrypter struct {
	key    Cipher
	source NonceSource
}

// Encrypt creates a new AEAD cipher with associated data.
func (e Encrypter) Encrypt(ad []byte) (aead.Cipher, error) {
	if nonce, ok := e.source.Next(); ok {
		return e.key.Encrypt(nonce, ad), nil
	}
	return nil, ErrNonceSourceOverflow
}

// Encrypt encrypts the data without internal buffering.
func (e Encrypter) EncryptData(data, ad []byte) (Data, error) {
	if nonce, ok := e.source.Next(); ok {
		return e.key.EncryptData(data, nonce, ad), nil
	}
	return Data{}, ErrNonceSourceOverflow
}

// Encrypt encrypts the data.
func (e Encrypter) EncryptDataBuf(data, ad []byte) (Data, error) {
	if nonce, ok := e.source.Next(); ok {
		return e.key.EncryptDataBuf(data, nonce, ad), nil
	}
	return Data{}, ErrNonceSourceOverflow
}
