package backup

import (
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/internal"
)

// EncryptKey encrypts a key with the given crypter.
func EncryptKey(key crypto.Key, crypter *encrypted.Crypter) (Key, error) {
	fp := key.Fingerprint()
	data, err := crypter.EncryptData(key.Pack(), fp.Bytes())
	if err != nil {
		return Key{}, err
	}
	return Key{
		Algorithm: strings.ToUpper(key.Scheme().Name()),
		FP:        fp,
		Data:      data,
	}, nil
}

// Key represents an encrypted private key.
type Key struct {
	Algorithm string             `msgpack:"alg"`
	FP        crypto.Fingerprint `msgpack:"fp"`
	Data      encrypted.Data     `msgpack:"data"`
}

// Decrypt decrypts the key with the given crypter.
func (k *Key) Decrypt(crypter *encrypted.Crypter) (crypto.Key, error) {
	dec, err := crypter.DecryptDataBuf(k.Data, k.FP.Bytes())
	if err != nil {
		return nil, err
	}

	var key crypto.Key
	if scheme := sign.ByName(k.Algorithm); scheme != nil {
		key, err = scheme.UnpackPrivate(dec)
	} else if scheme := kem.ByName(k.Algorithm); scheme != nil {
		key, err = scheme.UnpackPrivate(dec)
	} else {
		err = internal.ErrUnknownScheme
	}
	return key, err
}
