package encrypted

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
)

// Encapsulate encapsulates a random shared secret for recipient and creates a
// shared secret based encrypter.
func Encapsulate(scheme Secret,
	recipient kem.PublicKey,
	nonce, associatedData []byte,
) (aead.Cipher, *SharedSecret, error) {
	seed := crypto.Rand(recipient.Scheme().(kem.Scheme).EncapsulationSeedSize())
	ct, ss, err := recipient.Encapsulate(seed)
	if err != nil {
		return nil, nil, err
	}
	crypter, err := scheme.Encrypter(nonce, ss, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return crypter, &SharedSecret{
		Recepient: recipient.Fingerprint(),
		Scheme:    scheme,
		Secret:    ct,
	}, nil
}

// SharedSecret contains recipient, encapsulated shared secret and symmetric encryption parameters.
type SharedSecret struct {
	// Symmetric encryption scheme.
	Scheme Secret `msgpack:"scheme"`

	// encapsulated shared secret.
	Secret []byte `msgpack:"secret"`

	// Key fingerprint used for encapsulation.
	Recepient crypto.Fingerprint `msgpack:"recipient"`
}

// Decapsulate decapsulates the shared secret and creates a shared secret based decrypter.
func (e SharedSecret) Decapsulate(recipient kem.PrivateKey, nonce, ad []byte) (aead.Cipher, error) {
	if e.Recepient != recipient.Fingerprint() {
		return nil, errors.New("wrong recipient")
	}
	sharedSecret, err := recipient.Decapsulate(e.Secret)
	if err != nil {
		return nil, err
	}
	return e.Scheme.Decrypter(nonce, sharedSecret, ad)
}
