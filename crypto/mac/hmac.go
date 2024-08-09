package mac

import (
	hmacpkg "crypto/hmac"

	"github.com/karalef/quark/crypto/hash"
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

func newCustom(h hash.Scheme, keySize, maxKeySize int, new func([]byte) hash.Hash) Scheme {
	return New("HMAC_"+h.Name(), keySize, maxKeySize, h.Size(), h.BlockSize(), func(key []byte) MAC {
		return hmac{new(key)}
	})
}

// hmac schemes.
var (
	SHA256     = newHMAC(hash.SHA256)
	SHA3_256   = newHMAC(hash.SHA3_256)
	BLAKE2b128 = newCustom(hash.BLAKE2B128, 0, 64, func(key []byte) hash.Hash {
		h, _ := blake2b.New(16, key)
		return h
	})
	BLAKE2b256 = newCustom(hash.BLAKE2B256, 0, 64, func(key []byte) hash.Hash {
		h, _ := blake2b.New256(key)
		return h
	})
	BLAKE3 = newCustom(hash.BLAKE3, 0, 64, func(key []byte) hash.Hash {
		h, _ := blake2b.New512(key)
		return h
	})
)
