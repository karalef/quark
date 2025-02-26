package block

import "crypto/subtle"

// consts.
const (
	CMACBlockSize      = 16 // 128 bits
	cmacRB        byte = 0x87
)

// leftShift shifts the block one bit to the left
func leftShift(s *[CMACBlockSize]byte) {
	var carry byte = 0
	for i := len(s) - 1; i >= 0; i-- {
		b := s[i]
		s[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
}

func genSubkeys(block Cipher) (k1 [CMACBlockSize]byte, k2 [CMACBlockSize]byte) {
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

func processCMACBlock(block Cipher, x *[CMACBlockSize]byte, b []byte) {
	subtle.XORBytes(x[:], x[:], b)
	block.Encrypt(x[:], x[:])
}

// NewCMAC creates a new Cipher-based Message Authentication Code object.
func NewCMAC(block Cipher) *CMAC {
	if block.BlockSize() != CMACBlockSize {
		panic("CMAC requires a 128-bit block cipher")
	}
	k1, k2 := genSubkeys(block)
	return &CMAC{
		block: block,
		k1:    k1,
		k2:    k2,
	}
}

// CMAC is a Cipher-based Message Authentication Code.
type CMAC struct {
	block  Cipher
	k1, k2 [CMACBlockSize]byte
	x, b   [CMACBlockSize]byte
	n      uint8
}

func (c *CMAC) writeBlock(block []byte) {
	subtle.XORBytes(c.x[:], c.x[:], block)
	c.block.Encrypt(c.x[:], c.x[:])
}

// Reset resets the CMAC state.
func (c *CMAC) Reset() {
	c.n = 0
	clear(c.x[:])
}

// Write updates the CMAC state with the given data.
func (c *CMAC) Write(p []byte) {
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
	if c.n == CMACBlockSize {
		processCMACBlock(c.block, &c.x, c.b[:])
		c.n = 0
	}

	// write full blocks besides last
	for len(p) > CMACBlockSize {
		processCMACBlock(c.block, &c.x, p)
		p = p[CMACBlockSize:]
	}

	// buffer the last block
	c.n = uint8(copy(c.b[:], p))
}

// Sum appends the current CMAC state to the given data and returns the result.
// The Reset must be called before Write after Sum.
func (c *CMAC) Sum(dst []byte) []byte {
	k := c.k1
	if c.n != CMACBlockSize {
		clear(c.b[c.n+1:])
		c.b[c.n] = 0x80
		c.n = CMACBlockSize
		k = c.k2
	}
	subtle.XORBytes(c.b[:], c.b[:], k[:])
	processCMACBlock(c.block, &c.x, c.b[:])
	c.n = 0
	return append(dst, c.x[:]...)
}

// CMACTag computes the CMAC tag for a given message.
func CMACTag(dst []byte, block Cipher, msg []byte) []byte {
	K1, K2 := genSubkeys(block)

	n := len(msg)
	var lastBlock [CMACBlockSize]byte
	if l := n % CMACBlockSize; n > 0 && l == 0 {
		subtle.XORBytes(lastBlock[:], msg[n-CMACBlockSize:], K1[:])
	} else {
		copy(lastBlock[:], msg[n-l:])
		lastBlock[l] = 0x80
		subtle.XORBytes(lastBlock[:], lastBlock[:], K2[:])
	}

	var x [CMACBlockSize]byte
	for i := 0; i < n-CMACBlockSize; i += CMACBlockSize {
		processCMACBlock(block, &x, msg[i:i+CMACBlockSize])
	}

	processCMACBlock(block, &x, lastBlock[:])

	return append(dst, x[:]...)
}
