package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/karalef/quark/internal"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// Hash alias.
type Hash = hash.Hash

// Scheme represents a hash scheme and provides its parameters.
type Scheme interface {
	internal.Scheme
	Size() int
	BlockSize() int
	New() Hash
}

// NewFunc represents the function to create a hash.
type NewFunc func() Hash

// New creates new hash scheme.
// It does not register the scheme.
func New(name string, size, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		new:       new,
		name:      name,
		size:      size,
		blockSize: blockSize,
	}
}

type baseScheme struct {
	new       NewFunc
	name      string
	size      int
	blockSize int
}

func (s baseScheme) Name() string   { return s.name }
func (s baseScheme) Size() int      { return s.size }
func (s baseScheme) BlockSize() int { return s.blockSize }
func (s baseScheme) New() Hash      { return s.new() }

// schemes.
var (
	SHA256     = New("SHA256", sha256.Size, sha256.BlockSize, sha256.New)
	SHA512     = New("SHA512", sha512.Size, sha512.BlockSize, sha512.New)
	SHA3_256   = New("SHA3_256", 32, 136, sha3.New256)
	SHA3_512   = New("SHA3_512", 64, 72, sha3.New512)
	BLAKE2B128 = New("BLAKE2B_128", 16, blake2b.BlockSize, func() Hash {
		h, _ := blake2b.New(16, nil)
		return h
	})
	BLAKE2B256 = New("BLAKE2B_256", blake2b.Size256, blake2b.BlockSize, func() Hash {
		h, _ := blake2b.New256(nil)
		return h
	})
	BLAKE2B512 = New("BLAKE2B_512", blake2b.Size, blake2b.BlockSize, func() Hash {
		h, _ := blake2b.New512(nil)
		return h
	})
	BLAKE3 = New("BLAKE3", 32, 64, func() Hash {
		return blake3.New()
	})
)

var schemes = make(internal.Schemes[Scheme])

func init() {
	Register(SHA256)
	Register(SHA512)
	Register(SHA3_256)
	Register(SHA3_512)
	Register(BLAKE2B128)
	Register(BLAKE2B256)
	Register(BLAKE2B512)
	Register(BLAKE3)
}

// Register registers a hash scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the hash scheme by the provided name.
// Returns nil if the name is not registered.
func ByName(name string) Scheme { return schemes.ByName(name) }

// ListAll returns all registered hash algorithms.
func ListAll() []string { return schemes.ListAll() }

// ListSchemes returns all registered hash schemes.
func ListSchemes() []Scheme { return schemes.ListSchemes() }
