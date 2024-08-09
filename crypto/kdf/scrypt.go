package kdf

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/scrypt"
)

func init() {
	Register(Scrypt)
}

// Scrypt is a scrypt KDF.
var Scrypt KDF = New("scrypt", deriveScrypt)

func deriveScrypt(password, salt []byte, size int, params *ScryptParams) ([]byte, error) {
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

func (*ScryptParams) new() Params {
	return new(ScryptParams)
}

func (p ScryptParams) Encode() []byte {
	var b [8 + 8 + 8]byte
	binary.LittleEndian.PutUint64(b[:8], uint64(p.N))
	binary.LittleEndian.PutUint64(b[8:16], uint64(p.BlockMix))
	binary.LittleEndian.PutUint64(b[16:24], uint64(p.Parallelism))
	return b[:]
}

func (p *ScryptParams) Decode(b []byte) error {
	if len(b) < 24 {
		return errors.New("invalid scrypt parameters")
	}
	p.N = int(binary.LittleEndian.Uint64(b[:8]))
	p.BlockMix = int(binary.LittleEndian.Uint64(b[8:16]))
	p.Parallelism = int(binary.LittleEndian.Uint64(b[16:24]))
	return nil
}

// Validate always returns nil.
// Validation occurs during the key derivation.
func (p ScryptParams) Validate() error {
	return nil
}
