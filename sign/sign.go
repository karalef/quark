package sign

import "errors"

// Algorithm type.
type Algorithm string

// available algorithms.
const (
	// Dilithium2ED25519 hybrids Dilithium mode2 with ed25519
	Dilithium2ED25519 Algorithm = "DILITHIUM2_ED25519"

	// Dilithium3ED448 hybrids Dilithium mode3 with ed448
	Dilithium3ED448 Algorithm = "DILITHIUM3_ED448"

	Falcon1024 Algorithm = "FALCON1024"
	//Rainbow
)

// ListAll returns all available signature schemes.
func ListAll() []Scheme {
	a := make([]Scheme, 0, len(schemes))
	for _, v := range schemes {
		a = append(a, v)
	}
	return a
}

var schemes = map[Algorithm]Scheme{
	Dilithium2ED25519: dilithium2ed25519Scheme,
	Dilithium3ED448:   dilithium3ed448Scheme,
	Falcon1024:        falcon1024Scheme,
}

func (alg Algorithm) Alg() Algorithm { return alg }
func (alg Algorithm) Scheme() Scheme { return schemes[alg] }
func (alg Algorithm) IsValid() bool  { return alg.Scheme() != nil }

func (alg Algorithm) String() string {
	if !alg.IsValid() {
		return "INVALID"
	}
	return string(alg)
}

// Scheme represents signature scheme.
type Scheme interface {
	Alg() Algorithm

	// GenerateKey generates a new key-pair.
	GenerateKey() (PrivateKey, PublicKey, error)

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

// PrivateKey represents a signing private key.
type PrivateKey interface {
	Scheme() Scheme

	Equal(PrivateKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PrivateKeySize() length
	// and writes the private key to it.
	Bytes() []byte

	Sign(msg []byte) ([]byte, error)
}

// PublicKey represents a signing public key.
type PublicKey interface {
	Scheme() Scheme

	Equal(PublicKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PublicKeySize() length
	// and writes the public key to it.
	Bytes() []byte

	Verify(msg []byte, signature []byte) (bool, error)
}

// errors.
var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidSeedSize  = errors.New("invalid seed size")
	ErrInvalidKeySize   = errors.New("invalid key size")
)
