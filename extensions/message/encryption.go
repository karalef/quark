package message

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/secret"
)

// Encryption contains nonce and one of encryption types.
type Encryption struct {
	Nonce []byte `msgpack:"nonce"`

	Passphase        *Passphase        `msgpack:"passphase,omitempty"`
	KeyEstablishment *KeyEstablishment `msgpack:"key_establishment,omitempty"`
	GroupEncryption  *GroupEncryption  `msgpack:"group_encryption,omitempty"`
}

// IsPassphrased returns true if message is encrypted using password-based symmetric encryption.
func (e Encryption) IsPassphrased() bool { return e.Passphase != nil }

// IsEncapsulated returns true if message is encrypted using key encapsulation mechanism.
func (e Encryption) IsEncapsulated() bool { return e.KeyEstablishment != nil }

// IsGroup returns true if message is encrypted using public key encryption.
func (e Encryption) IsGroup() bool { return e.GroupEncryption != nil }

// Decrypt creates an authenticated cipher using password-based symmetric encryption.
func (e Encryption) Decrypt(passphrase string, ad []byte) (aead.Cipher, error) {
	return e.Passphase.Decrypt(passphrase, e.Nonce, ad)
}

// Decapsulate creates an authenticated cipher for recipient using encapsulated shared secret.
func (e Encryption) Decapsulate(recipient kem.PrivateKey, ad []byte) (aead.Cipher, error) {
	return e.KeyEstablishment.Decapsulate(recipient, e.Nonce, ad)
}

// DecryptTo creates an authenticated cipher for provided recipient.
func (e Encryption) DecryptTo(recipient pke.PrivateKey, ad []byte) (aead.Cipher, error) {
	return e.GroupEncryption.DecryptTo(recipient, e.Nonce, ad)
}

// Password uses password-based symmetric encryption to create an authenticated stream cipher.
func Password(passphrase string, ad []byte, params encrypted.PassphraseParams) (aead.Cipher, *Encryption, error) {
	pass := encrypted.NewPassphrase(params)
	crypter, err := pass.NewCrypter(passphrase)
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.Rand(params.Scheme.AEAD().NonceSize())
	aead, err := crypter.Encrypt(nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:     nonce,
		Passphase: &Passphase{Scheme: pass},
	}, nil
}

// Passphase contains passphrase-based symmetric encryption parameters.
type Passphase struct {
	Scheme encrypted.Passphrase `msgpack:"passphrase"`
}

// Decrypt creates an authenticated cipher using password-based symmetric encryption.
func (p Passphase) Decrypt(passphrase string, nonce, ad []byte) (aead.Cipher, error) {
	crypter, err := p.Scheme.NewCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return crypter.Decrypt(nonce, ad)
}

// Encapsulate generates and encapsulates a shared secret and creates an authenticated stream cipher.
func Encapsulate(scheme secret.Scheme, recipient kem.PublicKey, associatedData []byte) (aead.Cipher, *Encryption, error) {
	ciphertext, secret, err := kem.Encapsulate(recipient)
	if err != nil {
		return nil, nil, err
	}

	keyEst := KeyEstablishment{
		Recepient: recipient.Fingerprint(),
		Scheme:    encrypted.Secret(scheme),
		Secret:    ciphertext,
	}

	crypter, err := keyEst.Scheme.NewCrypter(secret)
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.Rand(scheme.AEAD().NonceSize())
	aead, err := crypter.Encrypt(nonce, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:            nonce,
		KeyEstablishment: &keyEst,
	}, err
}

// KeyEstablishment contains encapsulated shared secret with symmetric encryption parameters.
type KeyEstablishment struct {
	// Key fingerprint used for encapsulation.
	Recepient crypto.Fingerprint `msgpack:"recipient"`

	// Symmetric encryption scheme.
	Scheme encrypted.Secret `msgpack:"scheme"`

	// encapsulated shared secret.
	Secret []byte `msgpack:"secret"`
}

// Decapsulate creates an authenticated cipher for recipient using encapsulated shared secret.
func (e KeyEstablishment) Decapsulate(recipient kem.PrivateKey, nonce, ad []byte) (aead.Cipher, error) {
	if e.Recepient != recipient.Fingerprint() {
		return nil, errors.New("wrong recipient")
	}
	sharedSecret, err := recipient.Decapsulate(e.Secret)
	if err != nil {
		return nil, err
	}
	crypter, err := e.Scheme.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	return crypter.Decrypt(nonce, ad)
}

// Encrypt generates and encapsulates a shared secret for each recipient and creates an authenticated stream cipher.
func Encrypt(scheme secret.Scheme, recipients []pke.PublicKey, associatedData []byte) (aead.Cipher, *Encryption, error) {
	secretSize := 0
	maxSize := 0
	for _, recipient := range recipients {
		size := recipient.Scheme().(pke.Scheme).PlaintextSize()
		if secretSize == 0 {
			secretSize = size
			maxSize = size
			continue
		}
		secretSize = min(secretSize, size)
		maxSize = max(maxSize, size)
	}

	group := GroupEncryption{
		Scheme:  encrypted.Secret(scheme),
		Size:    uint(secretSize),
		Secrets: make(map[crypto.Fingerprint][]byte, len(recipients)),
	}
	secretBuf := crypto.Rand(maxSize)
	for _, recipient := range recipients {
		size := recipient.Scheme().(pke.Scheme).PlaintextSize()
		ct, err := pke.Encrypt(recipient, secretBuf[:size])
		if err != nil {
			return nil, nil, err
		}
		group.Secrets[recipient.Fingerprint()] = ct
	}

	crypter, err := group.Scheme.NewCrypter(secretBuf[:secretSize])
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.Rand(scheme.AEAD().NonceSize())
	aead, err := crypter.Encrypt(nonce, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:           nonce,
		GroupEncryption: &group,
	}, err
}

// GroupEncryption contains assymetrically encrypted shared secret for each recipient
// with symmetric encryption parameters.
type GroupEncryption struct {
	// Symmetric encryption scheme.
	Scheme encrypted.Secret `msgpack:"scheme"`

	// Size of the shared secret.
	Size uint `msgpack:"size"`

	// Secrets contains encrypted shared secrets related to recipients.
	Secrets map[crypto.Fingerprint][]byte `msgpack:"secrets"`
}

// DecryptTo creates an authenticated cipher for provided recipient.
func (e GroupEncryption) DecryptTo(recipient pke.PrivateKey, nonce, ad []byte) (aead.Cipher, error) {
	encryptedSecret, ok := e.Secrets[recipient.Fingerprint()]
	if !ok {
		return nil, errors.New("the message is not encrypted for provided recipient")
	}
	secret, err := recipient.Decrypt(encryptedSecret)
	if err != nil {
		return nil, err
	}
	crypter, err := e.Scheme.NewCrypter(secret[:e.Size])
	if err != nil {
		return nil, err
	}
	return crypter.Decrypt(nonce, ad)
}
