package mac

import (
	hmacpkg "crypto/hmac"

	"github.com/karalef/quark/crypto/hash"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

func init() {
	Register(SHA256)
	Register(SHA3_256)
	Register(BLAKE2b128)
	Register(BLAKE2b256)
	Register(BLAKE3)
}

var _ MAC = hmac{}

type hmac struct {
	hash.Hash
}

func (h hmac) Tag(b []byte) []byte { return h.Hash.Sum(b) }

func newHMAC(h hash.Scheme) Scheme {
	return New("HMAC_"+h.Name(), 0, 0, h.Size(), h.BlockSize(), func(key []byte) MAC {
		return hmac{hmacpkg.New(h.New, key)}
	})
}

// hmac schemes.
var (
	SHA256     = newHMAC(hash.SHA256)
	SHA3_256   = newHMAC(hash.SHA3_256)
	BLAKE2b128 = New(
		"HMAC_BLAKE2B128",
		0, 64, 16, blake2b.BlockSize,
		func(key []byte) MAC {
			h, _ := blake2b.New(16, key)
			return hmac{h}
		})
	BLAKE2b256 = New(
		"HMAC_"+hash.BLAKE2B256.Name(),
		0, 64, blake2b.Size256, blake2b.BlockSize,
		func(key []byte) MAC {
			h, _ := blake2b.New256(key)
			return hmac{h}
		})
	BLAKE3 = New(
		"HMAC_"+hash.BLAKE3.Name(),
		32, 0, hash.BLAKE3.Size(), hash.BLAKE3.BlockSize(),
		func(key []byte) MAC {
			h, _ := blake3.NewKeyed(key)
			return hmac{h}
		})
)
