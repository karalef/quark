package kdf

import "golang.org/x/crypto/scrypt"

// Scrypt is a scrypt KDF.
var Scrypt KDF = New("scrypt", deriveScrypt)

func deriveScrypt(password, salt []byte, size int, params ScryptParams) ([]byte, error) {
	return scrypt.Key(password, salt, params.N, params.BlockMix, params.Parallelism, size)
}

// ScryptParams contains the scrypt parameters.
type ScryptParams struct {
	// N parameter
	N int `msgpack:"N"`
	// r parameter
	BlockMix int `msgpack:"r"`
	// p parameter
	Parallelism int `msgpack:"p"`
}

// Validate always returns nil.
// Validation occurs during the key derivation.
func (p ScryptParams) Validate() error {
	return nil
}
