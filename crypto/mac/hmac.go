package mac

import (
	hmacpkg "crypto/hmac"
	"unsafe"

	"github.com/karalef/quark/crypto/hash"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

func init() {
	Schemes.Register(SHA256)
	Schemes.Register(SHA3)
	Schemes.Register(BLAKE2b128)
	Schemes.Register(BLAKE2b)
	Schemes.Register(BLAKE3_128)
	Schemes.Register(BLAKE3)
}

var _ State = hmac{}

type hmac struct {
	hash.State
}

func (h hmac) Tag(b []byte) []byte { return h.State.Sum(b) }

// NewHMAC creates new MAC scheme from specified parameters and hash function.
func NewHMAC(name string, size, blockSize int, keySize, maxKeySize int, new func([]byte) hash.State) Scheme {
	return New(name, keySize, maxKeySize, size, blockSize, func(key []byte) State {
		return hmac{new(key)}
	})
}

// NewHMACFrom creates new MAC scheme from hash scheme.
// It prepends "HMAC_" to the scheme name and uses the block size as a max key size.
func NewHMACFrom(h hash.Scheme) Scheme {
	bs := h.BlockSize()
	return NewHMAC("HMAC_"+h.Name(), h.Size(), bs, 0, bs, func(key []byte) hash.State {
		return hmacpkg.New(h.New, key)
	})
}

func newHMAC(h hash.Scheme, keySize, maxKeySize int, new func([]byte) hash.State) Scheme {
	return NewHMAC("HMAC_"+h.Name(), h.Size(), h.BlockSize(), keySize, maxKeySize, new)
}

// hmac schemes.
var (
	SHA256     = NewHMACFrom(hash.SHA256)
	SHA3       = NewHMACFrom(hash.SHA3)
	BLAKE2b128 = newHMAC(hash.BLAKE2b128, 0, 64, func(key []byte) hash.State {
		h, _ := blake2b.New(16, key)
		return h
	})
	BLAKE2b = newHMAC(hash.BLAKE2b256, 0, 64, func(key []byte) hash.State {
		h, _ := blake2b.New256(key)
		return h
	})
	BLAKE3_128 = newHMAC(hash.BLAKE3_128, 32, 0, blake3WithSize(16))
	BLAKE3     = newHMAC(hash.BLAKE3, 32, 0, func(key []byte) hash.State {
		h, _ := blake3.NewKeyed(key)
		return h
	})
)

func blake3WithSize(size int) func([]byte) hash.State {
	return func(key []byte) hash.State {
		h, _ := blake3.NewKeyed(key)
		*(*int)(unsafe.Pointer(h)) = size
		return h
	}
}
