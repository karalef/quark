package encrypted

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sync"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/encrypted/lfsr"
)

// NonceSource represents the source of nonce.
// It can be counter, random generator, something hybrid or whatever.
type NonceSource interface {
	// Size returns the nonce size in bytes.
	Size() uint8

	// Next return the next nonce and true if successful.
	// Returns false if the next nonce may repeat the previous one.
	Next() ([]byte, bool)
}

// NewCounter creates a new nonce source which increments the value by 1.
func NewCounter(size uint8) *Counter {
	if size == 0 {
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
	size  uint8
}

var one = big.NewInt(1)

func (n *Counter) Size() uint8 { return n.size }

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
func NewRandomNonce(size uint8, rnd io.Reader) *Random {
	if rnd == nil {
		rnd = rand.Reader
	}
	return &Random{
		rand: rnd,
		size: size,
	}
}

var _ NonceSource = (*Random)(nil)

// Random is a nonce source that generates random bytes.
type Random struct {
	rand io.Reader
	size uint8
	mut  sync.Mutex
}

func (r *Random) Size() uint8 { return r.size }

func (r *Random) Next() ([]byte, bool) {
	nonce := make([]byte, r.size)
	r.mut.Lock()
	if _, err := r.rand.Read(nonce); err != nil {
		panic(err)
	}
	r.mut.Unlock()
	return nonce, true
}

// NewLFSRNonce creates a new nonce source that uses LFSR.
// If seed is 0, it will be obtained from crypto/rand.
func NewLFSRNonce(size uint8, seed uint64) *LFSR {
	if size == 0 {
		panic("invalid nonce size")
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
	size uint8
	bs   int
	mut  sync.Mutex
}

func (l *LFSR) Size() uint8 { return l.size }

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

// Nonce is a single nonce.
// It is used to encrypt only one data where the NonceSource is needed.
// It never copies the nonce and always returns true.
type Nonce []byte

func (n Nonce) Size() uint8          { return uint8(len(n)) }
func (n Nonce) Next() ([]byte, bool) { return n, true }

// ErrNonceSourceOverflow is returned when the nonce source overflows.
var ErrNonceSourceOverflow = errors.New("nonce source overflow")
