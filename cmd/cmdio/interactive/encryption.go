package interactive

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/encrypted/password"
	"github.com/karalef/quark/encrypted/secret"
)

func SelectPassword(a aead.Scheme, k kdf.Scheme) (password.Scheme, error) {
	var err error
	if a == nil {
		a, err = SelectScheme("Select encryption scheme", aead.ListAll, aead.ByName)
		if err != nil {
			return password.Scheme{}, err
		}
	}
	if k == nil {
		k, err = SelectScheme("Select key derivation function", kdf.ListAll, kdf.ByName)
		if err != nil {
			return password.Scheme{}, err
		}
	}
	return password.Build(a, k), nil
}

func SelectSecret(a aead.Scheme, x xof.Scheme) (secret.Scheme, error) {
	var err error
	if a == nil {
		a, err = SelectScheme("Select encryption scheme", aead.ListAll, aead.ByName)
		if err != nil {
			return secret.Scheme{}, err
		}
	}
	if x == nil {
		x, err = SelectScheme("Select XOF", xof.ListAll, xof.ByName)
		if err != nil {
			return secret.Scheme{}, err
		}
	}
	return secret.Build(a, x), nil
}
