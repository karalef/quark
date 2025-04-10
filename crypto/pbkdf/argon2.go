package pbkdf

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

func init() {
	Schemes.Register(Argon2i)
	Schemes.Register(Argon2id)
}

// Argon2i KDF.
var Argon2i = New("argon2i", argon2i)

// Argon2id KDF.
var Argon2id = New("argon2id", argon2id)

func argon2i(password, salt []byte, size uint32, cost *Argon2Cost) []byte {
	return argon2.Key(password, salt, cost.Time, cost.Memory, cost.Threads, size)
}

func argon2id(password, salt []byte, size uint32, cost *Argon2Cost) []byte {
	return argon2.IDKey(password, salt, cost.Time, cost.Memory, cost.Threads, size)
}

// Argon2Cost represents the Argon2 key derivation function cost parameters.
type Argon2Cost struct {
	Time    uint32 `msgpack:"t"`
	Memory  uint32 `msgpack:"m"`
	Threads uint8  `msgpack:"p"`
}

func (cost *Argon2Cost) Validate() error {
	if cost.Time < 1 || cost.Threads < 1 {
		return errors.New("cost parameters too small")
	}
	return nil
}

func (*Argon2Cost) New() Cost { return &Argon2Cost{} }
