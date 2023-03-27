package kem

import (
	"errors"
	"io"
)

type Algorithm string

const (
	Kyber512  Algorithm = "KYBER512"
	Kyber768  Algorithm = "KYBER768"
	Kyber1024 Algorithm = "KYBER1024"
	Frodo     Algorithm = "FRODO640SHAKE"
)

var schemes = map[Algorithm]Scheme{
	Kyber512:  kyber512Scheme,
	Kyber768:  kyber768Scheme,
	Kyber1024: kyber1024Scheme,
	Frodo:     frodoScheme,
}

func (alg Algorithm) Alg() Algorithm { return alg }

func (alg Algorithm) Scheme() Scheme {
	return schemes[alg]
}

func (alg Algorithm) IsValid() bool {
	return alg.Scheme() != nil
}

func (alg Algorithm) String() string {
	if !alg.IsValid() {
		return "INVALID"
	}
	return string(alg)
}

func LoadPrivate(key []byte, alg Algorithm) (PrivateKey, error) {
	scheme := alg.Scheme()
	if scheme != nil {
		return nil, ErrInvalidKeyAlgorithm
	}
	return scheme.UnpackPrivate(key)
}

func LoadPublic(key []byte, alg Algorithm) (PublicKey, error) {
	scheme := alg.Scheme()
	if scheme == nil {
		return nil, ErrInvalidKeyAlgorithm
	}
	return scheme.UnpackPublic(key)
}

type Scheme interface {
	Alg() Algorithm

	// GenerateKey creates a new key-pair.
	GenerateKey(rand io.Reader) (PrivateKey, PublicKey, error)

	// DeriveKey derives a key-pair from a seed.
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PrivateKey, PublicKey)

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (PublicKey, error)

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (PrivateKey, error)

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of encapsulated keys.
	EncapsKeySize() int

	// Size of established shared keys.
	SharedKeySize() int

	// Size of seed.
	SeedSize() int
}

type PrivateKey interface {
	Public() PublicKey
	Scheme() Scheme

	Equal(PrivateKey) bool
	Pack() []byte

	Decapsulate(ciphertext []byte) ([]byte, error)
}

type PublicKey interface {
	Scheme() Scheme

	Equal(PublicKey) bool
	Pack() []byte

	Encapsulate() (ciphertext, secret []byte, err error)
}

var (
	ErrInvalidKeyAlgorithm = errors.New("invalid kem algorithm")
)
