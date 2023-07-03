package mac

import (
	hmacpkg "crypto/hmac"
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var _ MAC = hmac{}

type hmac struct {
	hash.Hash
}

func (h hmac) Tag(b []byte) []byte { return h.Hash.Sum(b) }

func newHMAC(newHash func() hash.Hash) NewFunc {
	return func(key []byte) MAC { return hmac{hmacpkg.New(newHash, key)} }
}

// hmac schemes.
var (
	SHA256     = New("SHA256", 32, sha256.Size, newHMAC(sha256.New))
	SHA3_256   = New("SHA3_256", 32, 32, newHMAC(sha3.New256))
	BLAKE2b128 = New("BLAKE2b128", 16, 16, func(key []byte) MAC {
		h, _ := blake2b.New(16, key)
		return hmac{h}
	})
	BLAKE2b256 = New("BLAKE2b256", 32, blake2b.Size256, func(key []byte) MAC {
		h, _ := blake2b.New256(key)
		return hmac{h}
	})
)
