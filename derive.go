package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/extract"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pbkdf"
	"github.com/karalef/quark/scheme"
)

// KeyDeriver is a key derivation function.
type KeyDeriver[Secret any] interface {
	DeriveKey(secret Secret, salt []byte, len uint) ([]byte, error)
}

// Deriver is a master key derivation function.
type Deriver[Secret any] interface {
	Derive(secret Secret, salt []byte) (kdf.KDF, error)
}

// Ciphered contains a key derivation function with a cipher algorithm.
type Ciphered[Deriver KeyDeriver[Secret], Secret any] struct {
	Salt    []byte         `msgpack:"salt"`
	Cipher  aead.Algorithm `msgpack:"cipher"`
	Deriver Deriver        `msgpack:"deriver"`
}

// Key derives a cipher key.
func (c Ciphered[_, Secret]) Key(s Secret) ([]byte, error) {
	return c.Deriver.DeriveKey(s, c.Salt, uint(c.Cipher.Scheme.KeySize()))
}

// New derives a new Cipher.
func (c Ciphered[D, Secret]) New(s Secret) (Cipher, error) {
	key, err := c.Key(s)
	if err != nil {
		return Cipher{}, err
	}
	return NewCipher(c.Cipher.Scheme, key)
}

var _ KeyDeriver[any] = Derivation[Deriver[any], any]{}

// Derivation is a salted deriver that can use any secret.
type Derivation[T Deriver[Secret], Secret any] struct {
	Deriver T      `msgpack:"deriver"`
	Salt    []byte `msgpack:"salt"`
}

// Derive derives the master key from the secret.
func (e Derivation[_, Secret]) Derive(secret Secret) (kdf.KDF, error) {
	return e.Deriver.Derive(secret, e.Salt)
}

// DeriveKey implements KeyDeriver.
func (e Derivation[_, Secret]) DeriveKey(secret Secret, salt []byte, len uint) ([]byte, error) {
	kdf, err := e.Derive(secret)
	if err != nil {
		return nil, err
	}
	return kdf.Derive(salt, len), nil
}

// Master contains a master key derivation function with a cipher scheme.
type Master[T Deriver[Secret], Secret any] struct {
	Deriver Derivation[T, Secret] `msgpack:"deriver"`
	Cipher  aead.Algorithm        `msgpack:"cipher"`
}

// NewMasterKey derives a master key from the secret.
func (m Master[T, Secret]) New(secret Secret) (MasterKey, error) {
	k, err := m.Deriver.Derive(secret)
	return NewMasterKey(m.Cipher.Scheme, k), err
}

// NewKeyExchange creates a new key exchange.
func NewKeyExchange[D KeyDeriver[kem.PrivateKey]](cipher aead.Scheme, salt []byte, deriver D) KeyExchange[D] {
	return KeyExchange[D]{
		Salt:    salt,
		Cipher:  scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
		Deriver: deriver,
	}
}

// KeyExchange is a KEM-based scheme to derive a cipher key.
type KeyExchange[Deriver KeyDeriver[kem.PrivateKey]] = Ciphered[Deriver, kem.PrivateKey]

// NewMasterKeyExchange creates a new master key exchange.
func NewMasterKeyExchange(
	recipient kem.PublicKey,
	sch extract.Scheme,
	cipher aead.Scheme,
	saltSize uint,
) (MasterKeyExchange, MasterKey, error) {
	enc, k, err := Encapsulate(recipient, sch, saltSize)
	if err != nil {
		return MasterKeyExchange{}, MasterKey{}, err
	}
	return MasterKeyExchange{
		Cipher:  scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
		Deriver: enc,
	}, NewMasterKey(cipher, k), nil
}

// MasterKeyExchange is a KEM-based scheme to derive a master key.
type MasterKeyExchange = Master[Decapsulator, kem.PrivateKey]

// Encapsulate encapsulates a random shared secret for recipient and creates a
// KDF with random salt.
func Encapsulate(recipient kem.PublicKey, sch extract.Scheme, saltSize uint) (Encapsulated, kdf.KDF, error) {
	ct, ss, err := kem.Encapsulate(recipient)
	if err != nil {
		return Encapsulated{}, nil, err
	}
	salted := extract.NewSalted(sch, saltSize)
	return Encapsulated{
		Deriver: Decapsulator{
			Ciphertext: ct,
			Extractor:  salted.Scheme,
		},
		Salt: salted.Salt,
	}, salted.Extract(ss), nil
}

// Encapsulated is a KEM-based scheme to derive a master key.
type Encapsulated = Derivation[Decapsulator, kem.PrivateKey]

// Decapsulator is a Deriver for encapsulated shared secret.
type Decapsulator struct {
	Ciphertext []byte            `msgpack:"ct"`
	Extractor  extract.Algorithm `msgpack:"ext"`
}

// Derive implements Deriver.
func (e Decapsulator) Derive(sk kem.PrivateKey, salt []byte) (kdf.KDF, error) {
	ss, err := sk.Decapsulate(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	return e.Extractor.Scheme.Extract(ss, salt), nil
}

// NewPassphrase creates a new passphrase-based scheme to derive the master key.
func NewPassphrase(sch pbkdf.Fixed, salt []byte, k kdf.Scheme) Passphrase {
	return Passphrase{
		Deriver: Passphraser{
			Scheme: sch,
			KDF:    scheme.NewAlgorithm[kdf.Scheme, kdf.Registry](k),
		},
		Salt: salt,
	}
}

// Passphrase is a passphrase-based scheme to derive the master key. The PBKDF
// is used instead of KDF extraction phase since the result has enough entropy.
type Passphrase = Derivation[Passphraser, []byte]

// Passphraser is a PBKDF-based deriver.
type Passphraser struct {
	Scheme pbkdf.Fixed   `msgpack:"scheme"`
	KDF    kdf.Algorithm `msgpack:"kdf"`
}

// Derive returns kdf.KDF derived from passphrase. It skips the master key
// extraction step since the key derived using PBKDF already has enough entropy.
func (m Passphraser) Derive(passphrase, salt []byte) (kdf.KDF, error) {
	master, err := m.Scheme.Derive(passphrase, salt)
	if err != nil {
		return nil, err
	}
	return m.KDF.Scheme.New(master), nil
}

// NewPassphrase creates a new passphrase-based scheme to derive a cipher key.
func NewPassphrased(cipher aead.Scheme, salt []byte, sch pbkdf.KDF) Passphrased {
	return Passphrased{
		Salt:    salt,
		Cipher:  scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
		Deriver: passphraseKey(sch),
	}
}

// Passphrased is a passphrase-based scheme to derive a cipher key.
type Passphrased = Ciphered[passphraseKey, []byte]

type passphraseKey pbkdf.KDF

func (p passphraseKey) DeriveKey(secret []byte, salt []byte, len uint) ([]byte, error) {
	return pbkdf.KDF(p).Derive(secret, salt, uint32(len))
}

// NewMasterPassphrase creates a new passphrase-based scheme to derive a master key.
func NewMasterPassphrase(cipher aead.Scheme, sch pbkdf.Fixed, salt []byte, k kdf.Scheme) MasterPassphrase {
	p := NewPassphrase(sch, salt, k)
	return MasterPassphrase{
		Deriver: p,
		Cipher:  scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
	}
}

// MasterPassphrase is a passphrase-based scheme to derive a master key.
type MasterPassphrase = Master[Passphraser, []byte]
