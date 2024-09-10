package key

import (
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/internal"
)

// EncryptElement encrypts a key with the given crypter.
func EncryptElement(key crypto.Key, crypter *encrypted.Crypter) (Element, error) {
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), fp.Bytes())
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
	FP        crypto.Fingerprint `msgpack:"fp"`
	Data      encrypted.Data     `msgpack:"data"`
}

// Decrypt decrypts the key with the given crypter.
func (e *Element) Decrypt(crypter *encrypted.Crypter) (crypto.Key, error) {
	data, err := crypter.DecryptDataBuf(e.Data, e.FP.Bytes())
	if err != nil {
		return nil, err
	}
	if scheme := sign.ByName(e.Algorithm); scheme != nil {
		return scheme.UnpackPrivate(data)
	}
	if scheme := kem.ByName(e.Algorithm); scheme != nil {
		return scheme.UnpackPrivate(data)
	}
	return nil, internal.ErrUnknownScheme
}
