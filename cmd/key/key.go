package key

import (
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/identity"
	"github.com/karalef/quark/extensions/subkey"
)

func Generate(scheme sign.Scheme) (*Key, sign.PrivateKey, error) {
	return GenerateWithValidity(scheme, quark.NewValidity(time.Now().Unix(), 0))
}

// GenerateWithValidity generates a new key using crypto/rand with given validity.
func GenerateWithValidity(scheme sign.Scheme, v quark.Validity) (*Key, sign.PrivateKey, error) {
	k, sk, err := quark.Generate(scheme, v)
	if err != nil {
		return nil, nil, err
	}
	return New(k, nil), sk, nil
}

// New constructs a new Key and assigns the corresponding certificates.
func New(k *quark.Key, certs []quark.Any) *Key {
	key := &Key{key: k, certs: make([]quark.Any, 0, len(certs))}
	for _, c := range certs {
		if k.Verify(c, c.GetSignature()) != nil {
			continue
		}
		key.certs = append(key.certs, c)
		switch c.CertType() {
		case subkey.CertTypeKEMSubkey, subkey.CertTypeSignSubkey:
			key.subkeys = append(key.subkeys, subkey.FromCertificate(quark.To[subkey.PublicKey](c)))
		case identity.CertTypeIdentity:
			key.identities = append(key.identities, identity.FromCertificate(quark.To[identity.UserID](c)))
		}
	}
	return key
}

type Key struct {
	key        *quark.Key
	subkeys    []*subkey.Subkey
	identities []*identity.Identity
	certs      []quark.Any
}

func (k Key) ID() crypto.ID { return k.key.KeyID() }

func (k Key) Fingerprint() crypto.Fingerprint { return k.key.Fingerprint() }

// SetValidity sets key validity.
func (k Key) SetValidity(sk sign.PrivateKey, v quark.Validity) error {
	return k.key.SetValidity(sk, v)
}

func (k Key) Revoke(sk sign.PrivateKey, t int64, reason string) error {
	return k.SetValidity(sk, k.key.Validity().Revoke(t, reason))
}
