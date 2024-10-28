package etm

import (
	"encoding/binary"
	"errors"

	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
)

// MinMACKeySize is the minimum size of the MAC key.
const MinMACKeySize = 16

// DeriveMACKey derives the MAC key from the cipher key and nonce. It uses nonce
// as IV and encrypts a zero block(s) to obtain the MAC key. Panics if size is
// less than MinMACKeySize.
func DeriveMACKey(cipher cipher.Scheme, key, nonce []byte, size uint) (cipher.Cipher, []byte, error) {
	bs, err := CheckMACKeySize(cipher, size)
	if err != nil {
		panic(err)
	}
	stream, err := cipher.New(key, nonce)
	if err != nil {
		return nil, nil, err
	}
	return stream, deriveMACKey(stream, size, bs), nil
}

// CheckMacKeySize checks that size is at least MinMACKeySize.
// Returns the block size of the cipher (for cases where the block size is unknown).
func CheckMACKeySize(cipher cipher.Scheme, size uint) (uint, error) {
	bs := cipher.BlockSize()
	if bs == 0 {
		bs = int(size)
	}
	if size < MinMACKeySize {
		return uint(bs), errMacKeySize
	}
	return uint(bs), nil
}

var errMacKeySize = errors.New("mac key size must be in range [MinMACKeySize, cipher.BlockSize()]")

// DeriveMACKeyFast is like DeriveMACKey but requires known block size and does
// not verifies the sizes of the key, nonce and mac key.
func DeriveMACKeyFast(cipher cipher.Scheme, key, nonce []byte, size uint) (cipher.Cipher, []byte) {
	return deriveMACKeyFast(cipher, key, nonce, size, uint(cipher.BlockSize()))
}

func deriveMACKeyFast(cipher cipher.Scheme, key, nonce []byte, size, bs uint) (cipher.Cipher, []byte) {
	stream, _ := cipher.New(key, nonce)
	return stream, deriveMACKey(stream, size, bs)
}

// deriveMACKey encrypts a zero blocks to obtain the MAC key.
// even if the cipher has no block size the bs must be equal to size.
func deriveMACKey(cipher cipher.Cipher, size, bs uint) []byte {
	blocks := size / bs
	if size%bs != 0 {
		blocks++
	}
	zeros := make([]byte, bs*blocks)
	cipher.XORKeyStream(zeros, zeros)
	return zeros[:size:size]
}

// NewMAC creates a new MAC state and writes the additional data to it with
// padding (if scheme.BlockSize() is not 0). This MAC state automatically
// writes paddings and sizes of ciphertext and additional data.
// Panics if key is not of length scheme.KeySize() or exeeds scheme.MaxKeySize().
func NewMAC(scheme mac.Scheme, key []byte, additionalData []byte) mac.State {
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
	state mac.State
	buf   []byte
	adLen int
	count int
}

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

func (s macState) Tag(b []byte) []byte {
	s.writePad(s.count)
	s.writeLen(s.adLen)
	s.writeLen(s.count)
	return s.state.Tag(b)
}
