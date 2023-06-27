package xof

import "golang.org/x/crypto/sha3"

// shake schemes.
var (
	Shake128 = scheme{NewShake128, "SHAKE128"}
	Shake256 = scheme{NewShake256, "SHAKE256"}
)

func NewShake128() State {
	return shakeXOF{sha3.NewShake128()}
}

func NewShake256() State {
	return shakeXOF{sha3.NewShake256()}
}

type shakeXOF struct{ sha3.ShakeHash }

func (shake shakeXOF) Clone() State {
	return shakeXOF{shake.ShakeHash.Clone()}
}
