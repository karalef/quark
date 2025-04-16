package hmac

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

// NewWith creates new HMAC scheme with specified parameters and hash function.
// It prepends "HMAC_" to the scheme name.
func NewWith(h hash.Scheme, keySize, maxKeySize int, newf func([]byte) hash.State) Scheme {
	return New("HMAC_"+h.Name(), keySize, maxKeySize, h.Size(), h.BlockSize(), newf)
}

// NewFrom creates new HMAC scheme from hash scheme.
// It prepends "HMAC_" to the scheme name and uses the block size as a max key size.
func NewFrom(h hash.Scheme) Scheme {
	return NewWith(h, 0, h.BlockSize(), func(key []byte) hash.State {
		return hmacpkg.New(h.New, key)
	})
}

// hmac schemes.
var (
	SHA256     = NewFrom(hash.SHA256)
	SHA3       = NewFrom(hash.SHA3)
	BLAKE2b128 = NewWith(hash.BLAKE2b128, 0, 64, func(key []byte) hash.State {
		h, _ := blake2b.New(16, key)
		return h
	})
	BLAKE2b = NewWith(hash.BLAKE2b256, 0, 64, func(key []byte) hash.State {
		h, _ := blake2b.New256(key)
		return h
	})
	BLAKE3_128 = NewWith(hash.BLAKE3_128, 32, 0, blake3WithSize(16))
	BLAKE3     = NewWith(hash.BLAKE3, 32, 0, func(key []byte) hash.State {
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
