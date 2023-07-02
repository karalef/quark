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

// hmac schemes.
var (
	SHA256 = baseScheme{
		name:    "SHA256",
		size:    sha256.Size,
		keySize: sha256.BlockSize,
		new:     func(key []byte) MAC { return hmac{hmacpkg.New(sha256.New, key)} },
	}
	SHA3_256 = baseScheme{
		name:    "SHA3_256",
		size:    32,
		keySize: 136,
		new:     func(key []byte) MAC { return hmac{hmacpkg.New(sha3.New256, key)} },
	}
	BLAKE2b128 = baseScheme{
		name:    "BLAKE2b128",
		size:    16,
		keySize: blake2b.BlockSize,
		new: func(key []byte) MAC {
			h, _ := blake2b.New(16, key)
			return hmac{h}
		},
	}
	BLAKE2b256 = baseScheme{
		name:    "BLAKE2b256",
		size:    blake2b.Size256,
		keySize: blake2b.BlockSize,
		new: func(key []byte) MAC {
			h, _ := blake2b.New256(key)
			return hmac{h}
		},
	}
)
