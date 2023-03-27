package quark

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type HashAlg string

const (
	HashSHA256 HashAlg = "SHA256"
	HashSHA384 HashAlg = "SHA384"
	HashSHA512 HashAlg = "SHA512"
)

var hashSchemes = map[HashAlg]HashScheme{
	HashSHA256: hashScheme{
		HashAlg:  HashSHA256,
		hashSize: 256 / 8,
		newFunc:  sha256.New,
		sumFunc: func(b []byte) []byte {
			h := sha256.Sum256(b)
			return h[:]
		},
	},
	HashSHA384: hashScheme{
		HashAlg:  HashSHA384,
		hashSize: 384 / 8,
		newFunc:  sha512.New384,
		sumFunc: func(b []byte) []byte {
			h := sha512.Sum384(b)
			return h[:]
		},
	},
	HashSHA512: hashScheme{
		HashAlg:  HashSHA512,
		hashSize: 512 / 8,
		newFunc:  sha512.New,
		sumFunc: func(b []byte) []byte {
			h := sha512.Sum512(b)
			return h[:]
		},
	},
}

func (alg HashAlg) Alg() HashAlg { return alg }

func (alg HashAlg) Scheme() HashScheme {
	return hashSchemes[alg]
}

func (alg HashAlg) IsValid() bool {
	return alg.Scheme() != nil
}

func (alg HashAlg) String() string {
	switch alg {
	case HashSHA256:
		return "SHA256"
	case HashSHA384:
		return "SHA384"
	case HashSHA512:
		return "SHA512"
	default:
		return "INVALID"
	}
}

type HashScheme interface {
	Alg() HashAlg
	Size() int
	HashFunc() hash.Hash
	Sum([]byte) []byte
}

var _ HashScheme = hashScheme{}

type hashScheme struct {
	HashAlg
	hashSize int
	newFunc  func() hash.Hash
	sumFunc  func([]byte) []byte
}

func (s hashScheme) Size() int {
	return s.hashSize
}

func (s hashScheme) HashFunc() hash.Hash {
	return s.newFunc()
}

func (s hashScheme) Sum(data []byte) []byte {
	return s.sumFunc(data)
}
