// package chacha20poly1305 provides the chacha20poly1305 implementation
// as a stream AEAD cipher.
package chacha20poly1305

import (
	"encoding/binary"

	"github.com/karalef/quark/crypto/aead/etm"
	"github.com/karalef/quark/crypto/aead/internal"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

// consts
const (
	KeySize    = chacha20.KeySize
	NonceSize  = chacha20.NonceSize
	NonceSizeX = chacha20.NonceSizeX
	TagSize    = poly1305.TagSize
)

// NewEncrypter creates a new encrypter for the given key and nonce.
// The nonce length must be NonceSize or NonceSizeX.
func NewEncrypter(key, nonce, additionalData []byte) internal.Cipher {
	return etm.NewEncrypter(newChaCha20(key, nonce, additionalData))
}

// NewDecrypter creates a new decrypter for the given key and nonce.
// The nonce length must be NonceSize or NonceSizeX.
func NewDecrypter(key, nonce, additionalData []byte) internal.Cipher {
	return etm.NewDecrypter(newChaCha20(key, nonce, additionalData))
}

func newChaCha20(key, nonce, additionalData []byte) (*chacha20.Cipher, *macState) {
	stream, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	var block [32]byte
	stream.XORKeyStream(block[:], block[:])
	stream.SetCounter(1)

	state := &macState{
		state: poly1305.New(&block),
		adLen: len(additionalData),
	}
	//nolint:errcheck
	state.state.Write(additionalData)
	state.writePad(len(additionalData))

	return stream, state
}

type macState struct {
	state *poly1305.MAC
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
	if rem := written % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		s.state.Write(buf[:padLen])
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
	return s.state.Sum(b)
}
