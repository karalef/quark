package xof

import "golang.org/x/crypto/sha3"

func init() {
	Schemes.Register(Shake128)
	Schemes.Register(Shake256)
}

// shake schemes.
var (
	Shake128 = New("SHAKE128", 168, NewShake128)
	Shake256 = New("SHAKE256", 136, NewShake256)
)

// NewShake128 creates a new SHAKE128 variable-output-length State.
func NewShake128() State {
	return shakeXOF{sha3.NewShake128()}
}

// NewShake256 creates a new SHAKE256 variable-output-length State.
func NewShake256() State {
	return shakeXOF{sha3.NewShake256()}
}

type shakeXOF struct{ sha3.ShakeHash }

func (shake shakeXOF) Clone() State {
	return shakeXOF{shake.ShakeHash.Clone()}
}
