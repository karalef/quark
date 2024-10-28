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
func NewEncrypter(passphrase string,
	source encrypted.NonceSource,
	p encrypted.PassphraseParams,
) (*Encrypter, encrypted.Passphrase, error) {
	pp := encrypted.NewPassphrase(p)
	crypter, err := pp.NewCrypter(passphrase)
	if err != nil {
		return nil, pp, err
	}
	if source == nil {
		source = encrypted.NewLFSRNonce(uint8(p.Scheme.AEAD().NonceSize()), 0)
	}
	return &Encrypter{
		crypter: crypter,
		source:  source,
	}, pp, nil
}

// Encrypter encrypts multiple keys using nonce source
type Encrypter struct {
	crypter *encrypted.Crypter
	source  encrypted.NonceSource
}

func (e *Encrypter) Encrypt(key crypto.Key) (Element, error) {
	if nonce, ok := e.source.Next(); ok {
		return EncryptElement(key, e.crypter, nonce)
	}
	return Element{}, encrypted.ErrNonceSourceOverflow
}

// EncryptElement encrypts a key with the given crypter.
func EncryptElement(key crypto.Key, crypter *encrypted.Crypter, nonce []byte) (Element, error) {
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), nonce, fp.Bytes())
	if err != nil {
		return Element{}, err
	}
	return Element{
		Algorithm: strings.ToUpper(key.Scheme().Name()),
		FP:        fp,
		Data:      data,
	}, nil
}

// Element represents the one of the encrypted keys.
type Element struct {
	Algorithm string             `msgpack:"alg"`
	Data      encrypted.Data     `msgpack:"data"`
	FP        crypto.Fingerprint `msgpack:"fp"`
}

// Decrypt decrypts the key with the given crypter.
func (e *Element) Decrypt(crypter *encrypted.Crypter) (crypto.Key, error) {
	data, err := crypter.DecryptDataBuf(e.Data, e.FP.Bytes())
	if err != nil {
		return nil, err
	}
	if key, err := sign.UnpackPrivate(e.Algorithm, data); err == nil {
		return key, nil
	}
	if key, err := kem.UnpackPrivate(e.Algorithm, data); err == nil {
		return key, nil
	}
	return nil, scheme.ErrUnknownScheme
}
