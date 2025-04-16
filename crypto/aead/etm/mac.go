package etm

import (
	"encoding/binary"
	"errors"

	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/hmac"
)

// MinMACKeySize is the minimum size of the MAC key.
const MinMACKeySize = 16

var errMacKeySize = errors.New("mac key size must be in range [MinMACKeySize, cipher.BlockSize()]")

// DeriveMACKey derives the MAC key from the cipher key and nonce. It uses
// nonce as IV and encrypts a zero block to obtain the MAC key. Panics if size
// or scheme.BlockSize() is less than MinMACKeySize.
func DeriveMACKey(scheme cipher.Scheme, key, nonce []byte, size uint) (cipher.Cipher, []byte) {
	bs := uint(scheme.BlockSize())
	if size < MinMACKeySize || size > bs {
		panic(errMacKeySize)
	}
	stream := scheme.New(key, nonce)
	return stream, DeriveMACKeyFast(stream, size, bs)
}

// DeriveMACKeyFast encrypts a zero block to obtain the MAC key. Even if the
// cipher has no block size the bs must be equal to size. It does not check any
// conditions, so it may panic or drain wrong bytes count from key stream.
func DeriveMACKeyFast(ciph cipher.Cipher, size, bs uint) []byte {
	block := make([]byte, bs)
	ciph.XORKeyStream(block, block)
	return block[:size:size]
}

// NewMAC creates a new MAC state and writes the additional data to it with
// padding. This MAC state automatically writes paddings and sizes of ciphertext
// and additional data.
func NewMAC(scheme hmac.Scheme, key []byte, additionalData []byte) hash.State {
	state := &macState{
		state: scheme.New(key),
		adLen: len(additionalData),
		buf:   make([]byte, scheme.BlockSize()),
	}
	//nolint:errcheck
	state.state.Write(additionalData)
	state.writePad(len(additionalData))
	return state
}

type macState struct {
	state hash.State
	buf   []byte
	adLen int
	count int
}

func (s macState) Size() int      { return s.state.Size() }
func (s macState) BlockSize() int { return len(s.buf) }
func (macState) Reset()           { panic("etm: EtM MAC state is not resettable") }

func (s *macState) Write(p []byte) (n int, err error) {
	n, err = s.state.Write(p)
	s.count += n
	return n, err
}

//nolint:errcheck
func (s macState) writePad(written int) {
	if len(s.buf) == 0 {
		return
	}
	if rem := written % len(s.buf); rem != 0 {
		s.state.Write(s.buf[:len(s.buf)-rem])
	}
}

//nolint:errcheck
func (s macState) writeLen(n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	s.state.Write(buf[:])
}

func (s macState) Sum(b []byte) []byte {
	s.writePad(s.count)
	s.writeLen(s.adLen)
	s.writeLen(s.count)
	return s.state.Sum(b)
}
