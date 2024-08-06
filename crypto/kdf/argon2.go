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
var Argon2i = New("argon2i", argon2i)

// Argon2id KDF.
var Argon2id = New("argon2id", argon2id)

func argon2i(password, salt []byte, size int, params Argon2Params) ([]byte, error) {
	return argon2.Key(password, salt, params.Rounds, params.Memory, params.Threads, uint32(size)), nil
}

func argon2id(password, salt []byte, size int, params Argon2Params) ([]byte, error) {
	return argon2.IDKey(password, salt, params.Rounds, params.Memory, params.Threads, uint32(size)), nil
}

// Argon2Params contains the argon2 parameters.
type Argon2Params struct {
	Rounds  uint32 `msgpack:"rounds"`
	Memory  uint32 `msgpack:"memory"`
	Threads uint8  `msgpack:"parallelism"`
}

// Validate validates the argon2 parameters.
func (p Argon2Params) Validate() error {
	if p.Rounds < 1 {
		return errors.New("number of rounds too small")
	}
	if p.Threads < 1 {
		return errors.New("parallelism degree too low")
	}
	return nil
}
