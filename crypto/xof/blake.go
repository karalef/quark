package xof

import (
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// blake xofs.
var (
	BLAKE2xb = scheme{NewBLAKE2xb, "BLAKE2xb"}
	BLAKE3x  = scheme{NewBLAKE3x, "BLAKE3x"}
)

func NewBLAKE2xb() State {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	return blakeXOF{xof}
}

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
