package encrypted

import (
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/scheme"
)

// NewKeyEncrypter returns a new multiple keys encrypter with nonce source.
// If the nonce source is nil, LFSRNonce is used.
func NewKeyEncrypter[T crypto.Key](passphrase string, source NonceSource, p Passphrased) (*KeyEncrypter[T], error) {
	crypter, err := p.Crypter(passphrase)
	if err != nil {
		return nil, err
	}
	return NewKeyEncrypterFrom[T](crypter, source), nil
}

// NewKeyEncrypterFrom returns a new multiple keys encrypter from the given crypter and nonce source.
// If the nonce source is nil, LFSRNonce is used.
func NewKeyEncrypterFrom[T crypto.Key](crypter *Crypter, source NonceSource) *KeyEncrypter[T] {
	if source == nil {
		source = NewLFSRNonce(crypter.NonceSize(), 0)
	}
	return &KeyEncrypter[T]{
		crypter: crypter,
		source:  source,
	}
}

// KeyEncrypter encrypts multiple keys using nonce source.
type KeyEncrypter[T crypto.Key] struct {
	crypter *Crypter
	source  NonceSource
}

// Encrypt encrypts the key.
func (e *KeyEncrypter[T]) Encrypt(key T) (Key[T], error) {
	if nonce, ok := e.source.Next(); ok {
		return EncryptKey[T](key, e.crypter, nonce)
	}
	return Key[T]{}, ErrNonceSourceOverflow
}

// EncryptKey encrypts a key with the given crypter.
func EncryptKey[T crypto.Key](key T, crypter *Crypter, nonce []byte) (Key[T], error) {
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), nonce, fp.Bytes())
	if err != nil {
		return Key[T]{}, err
	}
	return Key[T]{
		Algorithm: strings.ToUpper(key.Scheme().Name()),
		FP:        fp,
		Data:      data,
	}, nil
}

// Key contains the encrypted key.
type Key[T crypto.Key] struct {
	Algorithm string             `msgpack:"alg"`
	Data      Data               `msgpack:"data"`
	FP        crypto.Fingerprint `msgpack:"fp"`
}

// DecryptMaterial decrypts the key material with the given crypter.
func (s *Key[_]) DecryptMaterial(crypter *Crypter) ([]byte, error) {
	return crypter.DecryptDataBuf(s.Data, s.FP.Bytes())
}

// Decrypt decrypts the key with the given crypter.
func (k *Key[T]) Decrypt(crypter *Crypter) (key T, err error) {
	material, err := k.DecryptMaterial(crypter)
	if err != nil {
		return
	}
	var unpacked crypto.Key
	if _, ok := crypto.Key(key).(sign.PrivateKey); ok {
		unpacked, err = sign.UnpackPrivate(k.Algorithm, material)
	} else if _, ok := crypto.Key(key).(kem.PrivateKey); ok {
		unpacked, err = kem.UnpackPrivate(k.Algorithm, material)
	} else if _, ok := crypto.Key(key).(pke.PrivateKey); ok {
		unpacked, err = pke.UnpackPrivate(k.Algorithm, material)
	} else {
		unpacked, err = k.unpackAny(material)
	}
	if err != nil {
		return
	}
	return unpacked.(T), nil
}

func (s *Key[_]) unpackAny(material []byte) (crypto.Key, error) {
	if k, err := sign.UnpackPrivate(s.Algorithm, material); err == nil {
		return k, nil
	}
	if k, err := kem.UnpackPrivate(s.Algorithm, material); err == nil {
		return k, nil
	}
	if k, err := pke.UnpackPrivate(s.Algorithm, material); err == nil {
		return k, nil
	}
	return nil, scheme.ErrUnknownScheme
}

// DecryptKey decrypts the key with the given crypter.
func (s *Key[_]) DecryptKey(crypter *Crypter) (crypto.Key, error) {
	material, err := s.DecryptMaterial(crypter)
	if err != nil {
		return nil, err
	}
	return s.unpackAny(material)
}

// DecryptSign decrypts the sign key with the given crypter.
func (s *Key[_]) DecryptSign(crypter *Crypter) (sign.PrivateKey, error) {
	material, err := s.DecryptMaterial(crypter)
	if err != nil {
		return nil, err
	}
	return sign.UnpackPrivate(s.Algorithm, material)
}

// DecryptKEM decrypts the KEM key with the given crypter.
func (s *Key[_]) DecryptKEM(crypter *Crypter) (kem.PrivateKey, error) {
	material, err := s.DecryptMaterial(crypter)
	if err != nil {
		return nil, err
	}
	return kem.UnpackPrivate(s.Algorithm, material)
}

// DecryptPKE decrypts the PKE key with the given crypter.
func (s *Key[_]) DecryptPKE(crypter *Crypter) (pke.PrivateKey, error) {
	material, err := s.DecryptMaterial(crypter)
	if err != nil {
		return nil, err
	}
	return pke.UnpackPrivate(s.Algorithm, material)
}
