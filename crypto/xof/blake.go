package xof

import (
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

func init() {
	Register(BLAKE2xb)
	Register(BLAKE3x)
}

// blake xofs.
var (
	BLAKE2xb = New("BLAKE2xb", 64, NewBLAKE2xb)
	BLAKE3x  = New("BLAKE3x", 64, NewBLAKE3x)
)

// NewBLAKE2xb creates a new BLAKE2b variable-output-length State.
func NewBLAKE2xb() State {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	return blakeXOF{xof}
}

// NewBLAKE3x creates a new BLAKE3 variable-output-length State.
func NewBLAKE3x() State {
	return &blake3XOF{h: blake3.New()}
}

type blakeXOF struct{ blake2b.XOF }

func (blake blakeXOF) Clone() State {
	return blakeXOF{blake.XOF.Clone()}
}

type blake3XOF struct {
	h *blake3.Hasher
	d *blake3.Digest
}

func (blake *blake3XOF) Clone() State {
	return &blake3XOF{h: blake.h.Clone(), d: blake.d}
}

func (blake *blake3XOF) Reset() {
	blake.h.Reset()
	blake.d = nil
}

func (blake *blake3XOF) Write(p []byte) (int, error) {
	if blake.d != nil {
		panic("xof: write after read")
	}
	return blake.h.Write(p)
}

func (blake *blake3XOF) Read(p []byte) (int, error) {
	if blake.d == nil {
		blake.d = blake.h.Digest()
	}
	return blake.d.Read(p)
}
