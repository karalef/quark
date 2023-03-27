package sign

import (
	"errors"
	"io"
)

type Algorithm string

const (
	// Dilithium2 hybrids Dilithium mode2 with ed25519
	Dilithium2 Algorithm = "DILITHIUM2ED25519"

	// Dilithium3 hybrids Dilithium mode3 with ed448
	Dilithium3 Algorithm = "DILITHIUM3ED448"

	//Falcon
	//Rainbow
)

var schemes = map[Algorithm]Scheme{
	Dilithium2: dilithium2ed25519Scheme,
	Dilithium3: dilithium3ed448Scheme,
}

func (alg Algorithm) Alg() Algorithm {
	return alg
}

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
	if scheme == nil {
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

// Scheme represents signature scheme.
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

	// Size of signatures.
	SignatureSize() int

	// Size of seed.
	SeedSize() int
}

type PrivateKey interface {
	Public() PublicKey
	Scheme() Scheme

	Equal(PrivateKey) bool
	Pack() []byte

	Sign(msg []byte) ([]byte, error)
}

type PublicKey interface {
	Scheme() Scheme

	Equal(PublicKey) bool
	Pack() []byte

	Verify(msg []byte, signature []byte) (bool, error)
}

// errors.
var (
	ErrInvalidSignatureSize = errors.New("invalid signature size")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidKeyAlgorithm  = errors.New("invalid key algorithm")
)
