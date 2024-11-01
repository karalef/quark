package key

import (
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/scheme"
)

// NewEncrypter returns a new multiple keys encrypter with nonce source.
// If the nonce source is nil, LFSRNonce is used.
func NewEncrypter(passphrase string, source encrypted.NonceSource, p encrypted.Passphrase) (*Encrypter, error) {
	crypter, err := p.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return NewEncrypterFrom(crypter, source), nil
}

// NewEncrypterFrom returns a new multiple keys encrypter from the given crypter and nonce source.
// If the nonce source is nil, LFSRNonce is used.
func NewEncrypterFrom(crypter *encrypted.Crypter, source encrypted.NonceSource) *Encrypter {
	if source == nil {
		source = encrypted.NewLFSRNonce(uint8(crypter.NonceSize()), 0)
	}
	return &Encrypter{
		crypter: crypter,
		source:  source,
	}
}

// Encrypter encrypts multiple keys using nonce source.
type Encrypter struct {
	crypter *encrypted.Crypter
	source  encrypted.NonceSource
}

func (e *Encrypter) Encrypt(key crypto.Key) (Sub, error) {
	if nonce, ok := e.source.Next(); ok {
		return EncryptSub(key, e.crypter, nonce)
	}
	return Sub{}, encrypted.ErrNonceSourceOverflow
}

// EncryptSub encrypts a key with the given crypter.
func EncryptSub(key crypto.Key, crypter *encrypted.Crypter, nonce []byte) (Sub, error) {
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), nonce, fp.Bytes())
	if err != nil {
		return Sub{}, err
	}
	return Sub{
		Algorithm: strings.ToUpper(key.Scheme().Name()),
		FP:        fp,
		Data:      data,
	}, nil
}

// Sub represents the one of the encrypted keys.
type Sub struct {
	Algorithm string             `msgpack:"alg"`
	Data      encrypted.Data     `msgpack:"data"`
	FP        crypto.Fingerprint `msgpack:"fp"`
}

// Decrypt decrypts the key with the given crypter.
func (s *Sub) Decrypt(crypter *encrypted.Crypter) ([]byte, error) {
	return crypter.DecryptDataBuf(s.Data, s.FP.Bytes())
}

// DecryptKey decrypts the key with the given crypter.
func (s *Sub) DecryptKey(crypter *encrypted.Crypter) (crypto.Key, error) {
	material, err := s.Decrypt(crypter)
	if err != nil {
		return nil, err
	}
	if k, err := sign.UnpackPrivate(s.Algorithm, material); err == nil {
		return k, nil
	}
	if k, err := kem.UnpackPrivate(s.Algorithm, material); err == nil {
		return k, nil
	}
	return nil, scheme.ErrUnknownScheme
}

// Decrypt decrypts the sign key with the given crypter.
func (s *Sub) DecryptSign(crypter *encrypted.Crypter) (sign.PrivateKey, error) {
	material, err := s.Decrypt(crypter)
	if err != nil {
		return nil, err
	}
	return sign.UnpackPrivate(s.Algorithm, material)
}

// Decrypt decrypts the KEM key with the given crypter.
func (s *Sub) DecryptKEM(crypter *encrypted.Crypter) (kem.PrivateKey, error) {
	material, err := s.Decrypt(crypter)
	if err != nil {
		return nil, err
	}
	return kem.UnpackPrivate(s.Algorithm, material)
}
