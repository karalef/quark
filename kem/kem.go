package kem

// Algorithm type.
type Algorithm string

// available KEM algorithms.
const (
	Kyber512  Algorithm = "KYBER512"
	Kyber768  Algorithm = "KYBER768"
	Kyber1024 Algorithm = "KYBER1024"
	Frodo640  Algorithm = "FRODO640SHAKE"
)

// ListAll returns all available KEM schemes.
func ListAll() []Scheme {
	a := make([]Scheme, 0, len(schemes))
	for _, v := range schemes {
		a = append(a, v)
	}
	return a
}

var schemes = map[Algorithm]Scheme{
	Kyber512:  kyber512Scheme,
	Kyber768:  kyber768Scheme,
	Kyber1024: kyber1024Scheme,
	Frodo640:  frodoScheme,
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

// Scheme represents a KEM scheme.
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

	// Size of encapsulated shared secret.
	CiphertextSize() int

	// Size of shared secret.
	SharedSecretSize() int

	// Size of seed.
	SeedSize() int
}

// PrivateKey represents a KEM private key.
type PrivateKey interface {
	Public() PublicKey
	Scheme() Scheme

	Equal(PrivateKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PrivateKeySize() length
	// and writes the private key to it.
	Bytes() []byte

	// Decapsulate decapsulates the shared secret from the provided ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a KEM public key.
type PublicKey interface {
	Scheme() Scheme

	Equal(PublicKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PublicKeySize() length
	// and writes the public key to it.
	Bytes() []byte

	// Encapsulate encapsulates a randomly generated shared secret.
	Encapsulate() (ciphertext, secret []byte, err error)
}
