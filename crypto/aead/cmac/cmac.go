package cmac

import (
	"crypto/cipher"
	"crypto/subtle"
)

// consts.
const (
	BlockSize      = 16 // 128 bits
	cmacRB    byte = 0x87
)

// leftShift shifts the block one bit to the left
func leftShift(s *[BlockSize]byte) {
	var carry byte = 0
	for i := len(s) - 1; i >= 0; i-- {
		b := s[i]
		s[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
}

func genSubkeys(block cipher.Block) (k1 [BlockSize]byte, k2 [BlockSize]byte) {
	block.Encrypt(k1[:], k1[:])

	t := k1[0]
	leftShift(&k1)
	if t&0x80 != 0 {
		k1[len(k1)-1] ^= cmacRB
	}

	k2 = k1
	leftShift(&k2)
	if k1[0]&0x80 != 0 {
		k2[len(k2)-1] ^= cmacRB
	}

	return
}

func processBlock(block cipher.Block, x *[BlockSize]byte, b []byte) {
	subtle.XORBytes(x[:], x[:], b)
	block.Encrypt(x[:], x[:])
}

// New creates a new Cipher-based Message Authentication Code object.
func New(block cipher.Block) *State {
	if block.BlockSize() != BlockSize {
		panic("CMAC requires a 128-bit block cipher")
	}
	k1, k2 := genSubkeys(block)
	return &State{
		block: block,
		k1:    k1,
		k2:    k2,
	}
}

// State is a Cipher-based Message Authentication Code state.
type State struct {
	block  cipher.Block
	k1, k2 [BlockSize]byte
	x, b   [BlockSize]byte
	n      uint8
}

// Reset resets the CMAC state.
func (c *State) Reset() {
	c.n = 0
	clear(c.x[:])
}

// Write updates the CMAC state with the given data.
func (c *State) Write(p []byte) {
	if len(p) == 0 {
		return
	}

	// drain buffer
	n := copy(c.b[c.n:], p)
	c.n += uint8(n)
	p = p[n:]
	if len(p) == 0 {
		return
	}
	if c.n == BlockSize {
		processBlock(c.block, &c.x, c.b[:])
		c.n = 0
	}

	// write full blocks besides last
	for len(p) > BlockSize {
		processBlock(c.block, &c.x, p)
		p = p[BlockSize:]
	}

	// buffer the last block
	c.n = uint8(copy(c.b[:], p))
}

// Sum appends the current CMAC state to the given data and returns the result.
// The Reset must be called before Write after Sum.
func (c *State) Sum(dst []byte) []byte {
	k := c.k1
	if c.n != BlockSize {
		clear(c.b[c.n+1:])
		c.b[c.n] = 0x80
		c.n = BlockSize
		k = c.k2
	}
	subtle.XORBytes(c.b[:], c.b[:], k[:])
	processBlock(c.block, &c.x, c.b[:])
	c.n = 0
	return append(dst, c.x[:]...)
}

// Tag computes the CMAC tag for a given message.
func Tag(dst []byte, block cipher.Block, msg []byte) []byte {
	K1, K2 := genSubkeys(block)

	n := len(msg)
	var lastBlock [BlockSize]byte
	if l := n % BlockSize; n > 0 && l == 0 {
		subtle.XORBytes(lastBlock[:], msg[n-BlockSize:], K1[:])
	} else {
		copy(lastBlock[:], msg[n-l:])
		lastBlock[l] = 0x80
		subtle.XORBytes(lastBlock[:], lastBlock[:], K2[:])
	}

	var x [BlockSize]byte
	for i := 0; i < n-BlockSize; i += BlockSize {
		processBlock(block, &x, msg[i:i+BlockSize])
	}

	processBlock(block, &x, lastBlock[:])

	return append(dst, x[:]...)
}
