package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
)

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

// NewMasterKey returns a new master key.
func NewMasterKey(scheme aead.Scheme, kdf kdf.KDF) MasterKey {
	return MasterKey{
		sch: scheme,
		kdf: kdf,
	}
}

// MasterKey is a key used to derive a cipher keys.
type MasterKey struct {
	sch aead.Scheme
	kdf kdf.KDF
}

// Derive derives a key with the given info.
func (mk MasterKey) Derive(info []byte) []byte {
	return mk.kdf.Derive(info, uint(mk.sch.KeySize()))
}

// New derives a cipher key with the given info.
func (mk MasterKey) New(info []byte) (Cipher, error) {
	return NewCipher(mk.sch, mk.Derive(info))
}

// Encrypter returns a new encrypter using the key derived with info.
func (mk MasterKey) Encrypter(info []byte, prf PRF) (Encrypter, error) {
	k, err := mk.New(info)
	if err != nil {
		return Encrypter{}, err
	}
	return NewEncrypter(k, prf), nil
}

// NewNonceSource returns a new nonce source.
func NewNonceSource(prf PRF, size int) NonceSource {
	return NonceSource{prf: prf, size: size}
}

// NonceSource represents the source of nonce.
// It can be counter, random generator, something hybrid or whatever.
type NonceSource struct {
	prf  PRF
	size int
}

// Size returns the nonce size in bytes.
func (ns NonceSource) Size() int { return ns.size }

// Next return the next nonce.
func (ns NonceSource) Next() []byte {
	dst := make([]byte, ns.size)
	ns.prf.FillBytes(dst)
	return dst
}

// NewEncrypter returns a new encrypter from the given key and PRF that is used
// as a nonce source. If the prf is nil, LFSR is used.
func NewEncrypter(key Cipher, prf PRF) Encrypter {
	if prf == nil {
		prf = NewLFSR(LFSRBlockSize(key.NonceSize()), 0)
	}
	return Encrypter{
		key: key,
		ns:  NewNonceSource(prf, key.NonceSize()),
	}
}

// Encrypter encrypts multiple data using the PRF as a nonce source.
type Encrypter struct {
	key Cipher
	ns  NonceSource
}

// Encrypt creates a new AEAD cipher with associated data.
func (e Encrypter) Encrypt(ad []byte) aead.Cipher {
	return e.key.Encrypt(e.ns.Next(), ad)
}

// Encrypt encrypts the data without internal buffering.
func (e Encrypter) EncryptData(data, ad []byte) Data {
	return e.key.EncryptData(data, e.ns.Next(), ad)
}

// Encrypt encrypts the data.
func (e Encrypter) EncryptDataBuf(data, ad []byte) Data {
	return e.key.EncryptDataBuf(data, e.ns.Next(), ad)
}
