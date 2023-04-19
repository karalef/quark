package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

// Algorithm type.
type Algorithm string

// algorithms.
const (
	SHA256   Algorithm = "SHA256"
	SHA512   Algorithm = "SHA512"
	SHA3_256 Algorithm = "SHA3_256"
	SHA3_512 Algorithm = "SHA3_512"
)

// ListAll returns all available hash schemes.
func ListAll() []Scheme {
	schemes := make([]Scheme, 0, len(hashSchemes))
	for _, s := range hashSchemes {
		schemes = append(schemes, s)
	}
	return schemes
}

var hashSchemes = map[Algorithm]Scheme{
	SHA256: hashScheme{
		Algorithm: SHA256,
		hashSize:  sha256.Size,
		newFunc:   sha256.New,
		sumFunc: func(b []byte) []byte {
			h := sha256.Sum256(b)
			return h[:]
		},
	},
	SHA512: hashScheme{
		Algorithm: SHA512,
		hashSize:  sha512.Size,
		newFunc:   sha512.New,
		sumFunc: func(b []byte) []byte {
			h := sha512.Sum512(b)
			return h[:]
		},
	},
	SHA3_256: hashScheme{
		Algorithm: SHA3_256,
		hashSize:  32,
		newFunc:   sha3.New256,
		sumFunc: func(b []byte) []byte {
			h := sha3.Sum256(b)
			return h[:]
		},
	},
	SHA3_512: hashScheme{
		Algorithm: SHA3_512,
		hashSize:  64,
		newFunc:   sha3.New512,
		sumFunc: func(b []byte) []byte {
			h := sha3.Sum512(b)
			return h[:]
		},
	},
}

func (alg Algorithm) Alg() Algorithm { return alg }
func (alg Algorithm) Scheme() Scheme { return hashSchemes[alg] }
func (alg Algorithm) IsValid() bool  { return alg.Scheme() != nil }

func (alg Algorithm) String() string {
	if !alg.IsValid() {
		return "INVALID"
	}
	return string(alg)
}

// Scheme represents hash.
type Scheme interface {
	Alg() Algorithm
	Size() int
	Hash() hash.Hash
	Sum([]byte) []byte
}

var _ Scheme = hashScheme{}

type hashScheme struct {
	Algorithm
	hashSize int
	newFunc  func() hash.Hash
	sumFunc  func([]byte) []byte
}

func (s hashScheme) Size() int              { return s.hashSize }
func (s hashScheme) Hash() hash.Hash        { return s.newFunc() }
func (s hashScheme) Sum(data []byte) []byte { return s.sumFunc(data) }
