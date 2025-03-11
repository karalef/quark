package quark

import (
	"io"
	"math/big"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pkg/lfsr"
)

// PRF represents a pseudo-random function.
type PRF interface {
	FillBytes([]byte)
}

// NewCounter creates a new counter PRF which increments the value by 1.
func NewCounter() Counter { return Counter{big.NewInt(1)} }

var _ PRF = Counter{}

// Counter is a PRF that increments the value by 1.
type Counter struct{ ctr *big.Int }

var one = big.NewInt(1)

func (c Counter) FillBytes(dst []byte) {
	if c.ctr.BitLen() > len(dst)*8 {
		panic(io.ErrShortBuffer)
	}
	c.ctr.FillBytes(dst)
	c.ctr.Add(c.ctr, one)
}

// NewReader creates a new PRF from io.Reader.
func NewReader(r io.Reader) Reader { return Reader{r} }

var _ PRF = Reader{}

// Reader is an io.Reader that implements PRF.
type Reader struct{ r io.Reader }

func (r Reader) FillBytes(dst []byte) { _ = crypto.OrPanic(io.ReadFull(r.r, dst)) }

// NewLFSR creates a new PRF that uses LFSR.
// bs must be big as possible, len(dst)%bs == 0, one of 1, 2, 4, 8.
// If seed is 0, it will be obtained from crypto/rand.
func NewLFSR(bs int, seed uint64) LFSR {
	if seed == 0 {
		seed = crypto.RandUint64()
	}
	var l LFSR
	switch bs {
	case 8:
		l.lfsr = lfsr.New64(seed)
		l.bs = 8
	case 4:
		l.lfsr = lfsr.New32(uint32(seed & 0xffffffff))
		l.bs = 4
	case 2:
		l.lfsr = lfsr.New16(uint16(seed & 0xffff))
		l.bs = 2
	case 1:
		l.lfsr = lfsr.New8(uint8(seed & 0xff))
		l.bs = 1
	default:
		panic("invalid block size")
	}
	return l
}

// LFSRBlockSize returns the biggest possible block size for LFSR.
func LFSRBlockSize(s int) int {
	if s == 0 {
		panic("invalid size")
	}
	switch {
	case s%8 == 0:
		return 8
	case s%4 == 0:
		return 4
	case s%2 == 0:
		return 2
	default:
		return 1
	}
}

var _ PRF = LFSR{}

// LFSR is a PRF that uses LFSR.
type LFSR struct {
	lfsr lfsr.Bytes
	bs   int
}

func (l LFSR) FillBytes(dst []byte) {
	for i := 0; i < len(dst); i += l.bs {
		if !l.lfsr.NextBytes(dst[i : i+l.bs]) {
			panic(io.EOF)
		}
	}
}

// NewCBPRF creates a new PRF that uses CBPRF.
// The seed must be length of scheme.KeySize() + scheme.IVSize().
// If seed is nil, it will be obtained from crypto/rand.
func NewCBPRF(scheme cipher.Scheme, seed []byte) CBPRF {
	if seedSize := scheme.KeySize() + scheme.IVSize(); seed == nil {
		seed = crypto.Rand(seedSize)
	} else if len(seed) < seedSize {
		panic("seed must be length of scheme.KeySize() + scheme.IVSize()")
	}

	return CBPRF{c: scheme.New(seed[:scheme.KeySize()], seed[scheme.KeySize():])}
}

var _ PRF = CBPRF{}

// CBPRF is a cipher-based pseudo-random function.
type CBPRF struct{ c cipher.Cipher }

func (c CBPRF) FillBytes(dst []byte) {
	clear(dst)
	c.c.XORKeyStream(dst, dst)
}

// NewXPRF creates a new PRF that uses XOF.
// If the seed is empty, random 32 bytes will be used.
//
//nolint:errcheck
func NewXPRF(x xof.Scheme, seed []byte) XPRF {
	if len(seed) == 0 {
		seed = crypto.Rand(32)
	}
	s := x.New()
	s.Write(seed)
	return XPRF{x: s}
}

var _ PRF = XPRF{}

// NewXPRF is a XOF-based pseudo-random function.
type XPRF struct{ x xof.State }

//nolint:errcheck
func (x XPRF) FillBytes(dst []byte) { x.x.Read(dst) }
