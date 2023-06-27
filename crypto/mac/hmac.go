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
		keySize: 32,
		new:     func(key []byte) MAC { return hmac{hmacpkg.New(sha256.New, key)} },
	}
	SHA3_256 = baseScheme{
		name:    "SHA3_256",
		size:    32,
		keySize: 32,
		new:     func(key []byte) MAC { return hmac{hmacpkg.New(sha3.New256, key)} },
	}
	BLAKE2b128 = baseScheme{
		name:    "BLAKE2b_128",
		size:    16,
		keySize: 16,
		new: func(key []byte) MAC {
			h, _ := blake2b.New(16, key)
			return hmac{h}
		},
	}
	BLAKE2b128X = baseScheme{
		name:    "BLAKE2b_128X",
		size:    16,
		keySize: 32,
		new: func(key []byte) MAC {
			h, _ := blake2b.New(16, key)
			return hmac{h}
		},
	}
	BLAKE2b256 = baseScheme{
		name:    "BLAKE2b_256",
		size:    blake2b.Size256,
		keySize: 32,
		new: func(key []byte) MAC {
			h, _ := blake2b.New256(key)
			return hmac{h}
		},
	}
)
