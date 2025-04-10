package hash

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"hash"
	"unsafe"

	"github.com/karalef/quark/scheme"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// State is an stdlib hash.Hash alias.
type State = hash.Hash

// Scheme represents a hash scheme and provides its parameters.
type Scheme interface {
	scheme.Scheme
	Size() int
	BlockSize() int
	New() State
}

// NewFunc represents the function to create a hash.
type NewFunc func() State

// New creates new hash scheme.
// It does not register the scheme.
func New(name string, size, blockSize int, new NewFunc) Scheme {
	return baseScheme{
		String:    scheme.String(name),
		new:       new,
		size:      size,
		blockSize: blockSize,
	}
}

type baseScheme struct {
	scheme.String
	new       NewFunc
	size      int
	blockSize int
}

func (s baseScheme) Size() int      { return s.size }
func (s baseScheme) BlockSize() int { return s.blockSize }
func (s baseScheme) New() State     { return s.new() }

// schemes.
var (
	SHA256     = New("SHA256", sha256.Size, sha256.BlockSize, sha256.New)
	SHA512     = New("SHA512", sha512.Size, sha512.BlockSize, sha512.New)
	SHA3       = New("SHA3", 32, 136, func() State { return sha3.New256() })
	SHA3_512   = New("SHA3_512", 64, 72, func() State { return sha3.New512() })
	BLAKE2b128 = New("BLAKE2b_128", 16, blake2b.BlockSize, func() State {
		h, _ := blake2b.New(16, nil)
		return h
	})
	BLAKE2b256 = New("BLAKE2b_256", blake2b.Size256, blake2b.BlockSize, func() State {
		h, _ := blake2b.New256(nil)
		return h
	})
	BLAKE2b512 = New("BLAKE2b_512", blake2b.Size, blake2b.BlockSize, func() State {
		h, _ := blake2b.New512(nil)
		return h
	})
	BLAKE3     = New("BLAKE3", 32, 64, func() State { return blake3.New() })
	BLAKE3_128 = New("BLAKE3_128", 16, 64, blake3WithSize(16))
	BLAKE3_512 = New("BLAKE3_512", 64, 64, blake3WithSize(64))
)

func blake3WithSize(size int) func() State {
	return func() State {
		h := blake3.New()
		*(*int)(unsafe.Pointer(h)) = size
		return h
	}
}

// Schemes is a registry of hash schemes.
var Schemes = make(scheme.Map[Scheme])

func init() {
	Schemes.Register(SHA256)
	Schemes.Register(SHA512)
	Schemes.Register(SHA3)
	Schemes.Register(SHA3_512)
	Schemes.Register(BLAKE2b128)
	Schemes.Register(BLAKE2b256)
	Schemes.Register(BLAKE2b512)
	Schemes.Register(BLAKE3)
	Schemes.Register(BLAKE3_128)
	Schemes.Register(BLAKE3_512)
}

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }
