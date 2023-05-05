package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
)

// passphrased consts
const (
	SaltSize = 32
	IVSize   = aes.BlockSize
)

// ErrInvalidPassphrase is returned when the passphrase is empty.
var ErrInvalidPassphrase = errors.New("invalid passphrase")

// Argon2Opts represents options for argon2id.
type Argon2Opts struct {
	Time    uint32 // argon2id passes, if 0, will be set to draft RFC recommended value
	Memory  uint32 // argon2id memory, if 0, will be set to draft RFC recommended value
	Threads uint8  // argon2id threads, if 0, will be set to runtime.GOMAXPROCS(0).
}

// Argon2Default represents default options for argon2id.
var Argon2Default = Argon2Opts{
	Time:    1,
	Memory:  64 * 1024,
	Threads: uint8(runtime.GOMAXPROCS(0)),
}

// NewPassphrased returns a new stream cipher with derived key.
// Panics if the provided salt or iv sizes are not equal to SaltSize and IVSize or if the passphrase is empty.
// If opts is not provided, Argon2Default is used.
func NewPassphrased(passphrase string, salt, iv []byte, opts ...Argon2Opts) cipher.Stream {
	if len(passphrase) == 0 {
		panic("invalid passphrase")
	}
	if len(salt) != SaltSize {
		panic("invalid salt size")
	}
	if len(iv) != IVSize {
		panic("invalid iv size")
	}

	o := Argon2Default
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Time == 0 {
		o.Time = 1 // draft RFC recommended value
	}
	if o.Memory == 0 {
		o.Memory = 64 * 1024 // draft RFC recommended value
	}
	if o.Threads == 0 {
		o.Threads = uint8(runtime.GOMAXPROCS(0))
	}

	// derive aes256 key
	key := argon2.IDKey([]byte(passphrase), salt, o.Time, o.Memory, o.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // must never happen
	}

	return cipher.NewCTR(block, iv)
}

// Encrypt wraps a NewPassphrased stream cipher with cipher.StreamWriter.
func Encrypt(w io.Writer, passphrase string, iv, salt []byte, opts ...Argon2Opts) *cipher.StreamWriter {
	return &cipher.StreamWriter{
		S: NewPassphrased(passphrase, salt, iv, opts...),
		W: w,
	}
}

// Decrypt wraps a NewPassphrased stream cipher with cipher.StreamReader.
func Decrypt(r io.Reader, passphrase string, iv, salt []byte, opts ...Argon2Opts) *cipher.StreamReader {
	return &cipher.StreamReader{
		S: NewPassphrased(passphrase, salt, iv, opts...),
		R: r,
	}
}
