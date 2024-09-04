package kdf

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

func init() {
	Register(Argon2i)
	Register(Argon2id)
}

// Argon2i KDF.
var Argon2i = New("argon2i", argon2i, validateArgon2)

// Argon2id KDF.
var Argon2id = New("argon2id", argon2id, validateArgon2)

func argon2i(password, salt []byte, size int, cost Cost) []byte {
	return argon2.Key(password, salt, uint32(cost.CPU), uint32(cost.Memory), uint8(cost.Parallelism), uint32(size))
}

func argon2id(password, salt []byte, size int, cost Cost) []byte {
	return argon2.IDKey(password, salt, uint32(cost.CPU), uint32(cost.Memory), uint8(cost.Parallelism), uint32(size))
}

func validateArgon2(cost Cost) error {
	const maxUint8 = uint(^uint8(0))
	const maxUint32 = uint(^uint32(0))
	if cost.CPU < 1 || cost.Parallelism < 1 {
		return errors.New("cost parameters too small")
	}
	if cost.CPU > maxUint32 || cost.Memory > maxUint32 || cost.Parallelism > maxUint8 {
		return errors.New("cost parameters too large")
	}
	return nil
}
