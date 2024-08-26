package kdf

import (
	"encoding/binary"
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

func argon2i(password, salt []byte, size int, params *Argon2Params) ([]byte, error) {
	return argon2.Key(password, salt, params.Rounds, params.Memory, params.Threads, uint32(size)), nil
}

func argon2id(password, salt []byte, size int, params *Argon2Params) ([]byte, error) {
	return argon2.IDKey(password, salt, params.Rounds, params.Memory, params.Threads, uint32(size)), nil
}

// Argon2Params contains the argon2 parameters.
type Argon2Params struct {
	Rounds  uint32
	Memory  uint32
	Threads uint8
}

func (*Argon2Params) new() Params {
	return new(Argon2Params)
}

func (p Argon2Params) Encode() []byte {
	var b [4 + 4 + 1]byte
	binary.LittleEndian.PutUint32(b[:4], p.Rounds)
	binary.LittleEndian.PutUint32(b[4:8], p.Memory)
	b[8] = p.Threads
	return b[:]
}

func (p *Argon2Params) Decode(b []byte) error {
	if len(b) < 9 {
		return errors.New("invalid argon2 parameters")
	}
	p.Rounds = binary.LittleEndian.Uint32(b[:4])
	p.Memory = binary.LittleEndian.Uint32(b[4:8])
	p.Threads = b[8]
	return nil
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
