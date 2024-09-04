package kdf

import (
	"errors"

	"golang.org/x/crypto/scrypt"
)

func init() {
	Register(Scrypt)
}

// Scrypt is a scrypt KDF.
var Scrypt Scheme = New("scrypt", deriveScrypt, validateScrypt)

func deriveScrypt(password, salt []byte, size int, cost Cost) []byte {
	h, err := scrypt.Key(password, salt, int(cost.CPU), int(cost.Memory), int(cost.Parallelism), size)
	if err != nil {
		panic("unexpected scrypt error: " + err.Error())
	}
	return h
}

func validateScrypt(cost Cost) error {
	if cost.CPU <= 1 || cost.CPU&(cost.CPU-1) != 0 {
		return errors.New("N must be > 1 and a power of 2")
	}
	const maxMemory = ^uint(0) >> 9
	if cost.Memory*cost.Parallelism >= 1<<30 ||
		cost.Memory > (maxMemory<<1)/cost.Parallelism ||
		cost.Memory > maxMemory ||
		cost.CPU > (maxMemory<<1)/cost.Memory {
		return errors.New("parameters are too large")
	}
	return nil
}
