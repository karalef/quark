package pbkdf

import (
	"errors"

	"golang.org/x/crypto/scrypt"
)

func init() {
	Register(Scrypt)
}

// Scrypt is a scrypt KDF.
var Scrypt Scheme = New("scrypt", deriveScrypt)

func deriveScrypt(password, salt []byte, size uint32, cost *ScryptCost) []byte {
	h, err := scrypt.Key(password, salt, int(cost.N), int(cost.R), int(cost.P), int(size))
	if err != nil {
		panic("unexpected scrypt error: " + err.Error())
	}
	return h
}

// ScryptCost represents the Scrypt key derivation function cost parameters.
type ScryptCost struct {
	N uint `msgpack:"N"`
	R uint `msgpack:"r"`
	P uint `msgpack:"p"`
}

func (cost *ScryptCost) Validate() error {
	if cost.N <= 1 || cost.N&(cost.N-1) != 0 {
		return errors.New("N must be >1 and a power of 2")
	}
	const maxMemory = ^uint(0) >> 9
	if cost.R*cost.P >= 1<<30 ||
		cost.R > (maxMemory<<1)/cost.P ||
		cost.R > maxMemory ||
		cost.N > (maxMemory<<1)/cost.R {
		return errors.New("parameters are too large")
	}
	return nil
}

func (*ScryptCost) New() Cost { return &ScryptCost{} }
