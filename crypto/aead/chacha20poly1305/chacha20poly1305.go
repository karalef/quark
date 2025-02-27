// package chacha20poly1305 provides the chacha20poly1305 implementation
// as a stream AEAD cipher.
package chacha20poly1305

import (
	"encoding/binary"

	"github.com/karalef/quark/crypto/aead/internal"
	"golang.org/x/crypto/chacha20"

	//nolint:staticcheck
	"golang.org/x/crypto/poly1305"
)

// consts
const (
	KeySize    = chacha20.KeySize
	NonceSize  = chacha20.NonceSize
	NonceSizeX = chacha20.NonceSizeX
	TagSize    = poly1305.TagSize
)

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
// Panics if the key or nonce size is invalid.
func New(key, nonce, additionalData []byte) *Cipher {
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	var block [32]byte
	stream.XORKeyStream(block[:], block[:])
	stream.SetCounter(1)

	cipher := &Cipher{
		cipher: stream,
		state:  poly1305.New(&block),
		adLen:  len(additionalData),
	}
	//nolint:errcheck
	cipher.state.Write(additionalData)
	cipher.writePad(len(additionalData))

	return cipher
}

var _ internal.Cipher = (*Cipher)(nil)

type Cipher struct {
	cipher *chacha20.Cipher
	state  *poly1305.MAC
	adLen  int
	count  int
}

func (c *Cipher) Encrypt(dst, src []byte) {
	c.cipher.XORKeyStream(dst, src)
	c.write(dst[:len(src)])
}

func (c *Cipher) Decrypt(dst, src []byte) {
	c.write(src)
	c.cipher.XORKeyStream(dst, src)
}

func (*Cipher) TagSize() int { return TagSize }

func (c *Cipher) Tag(dst []byte) []byte {
	c.writePad(c.count)
	c.writeLen(c.adLen)
	c.writeLen(c.count)
	return c.state.Sum(dst)
}

func (c *Cipher) write(p []byte) {
	n, _ := c.state.Write(p)
	c.count += n
}

//nolint:errcheck
func (c *Cipher) writePad(written int) {
	if rem := written % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		c.state.Write(buf[:padLen])
	}
}

//nolint:errcheck
func (c *Cipher) writeLen(n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	c.state.Write(buf[:])
}
