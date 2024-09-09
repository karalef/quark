package encrypted

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/secret"
)

// NewSecret creates a new Secret with the given scheme.
func NewSecret(scheme secret.Scheme) Secret {
	return Secret{
		Secret: SecretHeader{XOF: XOF{scheme.XOF()}},
		Scheme: Scheme{Scheme: scheme.AEAD()},
	}
}

// Secret contains shared secret based encryption parameters.
type Secret struct {
	Secret SecretHeader `msgpack:"secret"`
	Scheme Scheme       `msgpack:"scheme"`
}

// NewCrypter creates a new Crypter with the given shared secret.
func (s Secret) NewCrypter(sharedSecret []byte) (*Crypter, error) {
	key, mackey, err := s.Secret.DeriveKeys(s.Scheme, sharedSecret)
	if err != nil {
		return nil, err
	}
	return NewCrypter(s.Scheme, key, mackey)
}

// SecretHeader contains parameters required to derive keys from a shared secret.
type SecretHeader struct {
	XOF XOF `msgpack:"xof,omitempty"`
}

func (s SecretHeader) Build(aead aead.Scheme) secret.Scheme {
	return secret.Build(aead, s.XOF)
}

func (s SecretHeader) DeriveKeys(aead aead.Scheme, sharedSecret []byte) ([]byte, []byte, error) {
	return secret.DeriveKeys(s.Build(aead), sharedSecret)
}
