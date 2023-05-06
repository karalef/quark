package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// passphrased consts
const (
	IVSize = aes.BlockSize

	TimeRFC     = 1
	MemoryRFC   = 64 * 1024
	SaltSizeRFC = 16
)

// IV is an IV for a passphrased cipher.
type IV [IVSize]byte

// ErrInvalidPassphrase is returned when the passphrase is empty.
var ErrInvalidPassphrase = errors.New("invalid passphrase")

// Argon2Params contains parameters for argon2id.
type Argon2Params struct {
	Time    uint32 // argon2id number of rounds
	Memory  uint32 // argon2id memory cost
	Threads uint8  // argon2id parallelism degree
}

// NewPassphrased returns a new stream cipher with derived key.
// Panics if the passphrase is empty.
func NewPassphrased(passphrase string, iv IV, salt []byte, params Argon2Params) cipher.Stream {
	if len(passphrase) == 0 {
		panic("invalid passphrase")
	}

	// derive aes256 key
	key := argon2.IDKey([]byte(passphrase), salt, params.Time, params.Memory, params.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // must never happen
	}

	return cipher.NewCTR(block, iv[:])
}

// StreamWriter is analogous to cipher.StreamWriter,
// but it does not allocate buffer, changing source bytes instead.
// Also it does not implement io.Closer.
type StreamWriter struct {
	S cipher.Stream
	W io.Writer
}

func (w *StreamWriter) Write(d []byte) (n int, err error) {
	w.S.XORKeyStream(d, d)
	n, err = w.W.Write(d)
	if n != len(d) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}

// Encrypt wraps a NewPassphrased stream cipher with StreamWriter.
func Encrypt(w io.Writer, passphrase string, iv IV, salt []byte, params Argon2Params) *StreamWriter {
	return &StreamWriter{
		S: NewPassphrased(passphrase, iv, salt, params),
		W: w,
	}
}

// EncryptWriter wraps a NewPassphrased stream cipher with cipher.StreamWriter.
func EncryptWriter(w io.Writer, passphrase string, iv IV, salt []byte, params Argon2Params) *cipher.StreamWriter {
	return &cipher.StreamWriter{
		S: NewPassphrased(passphrase, iv, salt, params),
		W: w,
	}
}

// Decrypt wraps a NewPassphrased stream cipher with cipher.StreamReader.
func Decrypt(r io.Reader, passphrase string, iv IV, salt []byte, params Argon2Params) *cipher.StreamReader {
	return &cipher.StreamReader{
		S: NewPassphrased(passphrase, iv, salt, params),
		R: r,
	}
}
