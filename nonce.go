package quark

import (
	"errors"
	"io"
	"math/big"
	"sync"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/pkg/lfsr"
)

// NonceSource represents the source of nonce.
// It can be counter, random generator, something hybrid or whatever.
type NonceSource interface {
	// Size returns the nonce size in bytes.
	Size() int

	// Next return the next nonce and true if successful.
	// Returns false if the next nonce may repeat the previous one.
	Next() ([]byte, bool)
}

// NewCounter creates a new nonce source which increments the value by 1.
func NewCounter(size int) *Counter {
	if size < 1 {
		panic(aead.ErrNonceSize)
	}
	return &Counter{
		value: big.NewInt(1),
		size:  size,
	}
}

var _ NonceSource = (*Counter)(nil)

// Counter is a nonce source that increments the value by 1.
type Counter struct {
	value *big.Int
	mut   sync.Mutex
	size  int
}

var one = big.NewInt(1)

func (n *Counter) Size() int { return n.size }

func (n *Counter) Next() ([]byte, bool) {
	nonce := make([]byte, n.size)
	n.mut.Lock()
	defer n.mut.Unlock()
	if n.value.BitLen() > int(n.size*8) {
		return nil, false
	}
	n.value.FillBytes(nonce)
	n.value.Add(n.value, one)
	return nonce, true
}

// NewRandomNonce creates a new nonce source that generates random bytes.
// Uses rand.Reader if rnd is nil.
func NewRandomNonce(size int, rnd io.Reader) *Random {
	if size < 1 {
		panic(aead.ErrNonceSize)
	}
	return &Random{
		rand: crypto.Reader(rnd),
		size: size,
	}
}

var _ NonceSource = (*Random)(nil)

// Random is a nonce source that generates random bytes.
type Random struct {
	rand io.Reader
	size int
	mut  sync.Mutex
}

func (r *Random) Size() int { return r.size }

func (r *Random) Next() ([]byte, bool) {
	nonce := make([]byte, r.size)
	r.mut.Lock()
	if _, err := io.ReadFull(r.rand, nonce); err != nil {
		panic(err)
	}
	r.mut.Unlock()
	return nonce, true
}

// NewLFSR creates a new nonce source that uses LFSR.
// If seed is 0, it will be obtained from crypto/rand.
func NewLFSR(size int, seed uint64) *LFSR {
	if size < 1 {
		panic(aead.ErrNonceSize)
	}
	if seed == 0 {
		seed = crypto.RandUint64()
	}
	l := &LFSR{
		size: size,
	}
	switch {
	case size%8 == 0:
		l.lfsr = lfsr.New64(seed)
		l.bs = 8
	case size%4 == 0:
		l.lfsr = lfsr.New32(uint32(seed & 0xffffffff))
		l.bs = 4
	case size%2 == 0:
		l.lfsr = lfsr.New16(uint16(seed & 0xffff))
		l.bs = 2
	default:
		l.lfsr = lfsr.New8(uint8(seed & 0xff))
		l.bs = 1
	}
	return l
}

var _ NonceSource = (*LFSR)(nil)

// LFSR is a nonce source that uses LFSR.
type LFSR struct {
	lfsr lfsr.Bytes
	size int
	bs   int
	mut  sync.Mutex
}

func (l *LFSR) Size() int { return l.size }

func (l *LFSR) Next() ([]byte, bool) {
	nonce := make([]byte, l.size)
	l.mut.Lock()
	defer l.mut.Unlock()
	for i := 0; i < int(l.size); i += l.bs {
		if !l.lfsr.NextBytes(nonce[i : i+l.bs]) {
			return nil, false
		}
	}
	return nonce, true
}

// NewCBPRF creates a new nonce source that uses CBPRF.
// The seed must be length of scheme.KeySize() + scheme.IVSize().
// If seed is nil, it will be obtained from crypto/rand.
func NewCBPRF(size int, scheme cipher.Scheme, seed []byte) *CBPRF {
	if size < 1 {
		panic(aead.ErrNonceSize)
	}
	seedSize := scheme.KeySize() + scheme.IVSize()
	if seed == nil {
		seed = crypto.Rand(seedSize)
	} else if len(seed) < seedSize {
		panic("seed must be length of scheme.KeySize() + scheme.IVSize()")
	}

	return &CBPRF{
		prf:  cipher.NewPRF(scheme, seed[:scheme.IVSize()], seed[scheme.IVSize():]),
		size: size,
	}
}

var _ NonceSource = (*CBPRF)(nil)

// CBPRF is a nonce source that uses cipher-based pseudo-random function.
type CBPRF struct {
	prf  cipher.PRF
	size int
	mut  sync.Mutex
}

func (c *CBPRF) Size() int { return c.size }

func (c *CBPRF) Next() ([]byte, bool) {
	nonce := make([]byte, c.size)
	c.mut.Lock()
	defer c.mut.Unlock()
	c.prf.ReadE(nonce)
	return nonce, true
}

var _ NonceSource = Nonce(nil)

// Nonce is a single nonce.
// It is used to encrypt only one data where the NonceSource is needed.
// It never copies the nonce and always returns true.
type Nonce []byte

func (n Nonce) Size() int            { return len(n) }
func (n Nonce) Next() ([]byte, bool) { return n, true }

// ErrNonceSourceOverflow is returned when the nonce source overflows.
var ErrNonceSourceOverflow = errors.New("nonce source overflow")
