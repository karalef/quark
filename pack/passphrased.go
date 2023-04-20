package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"runtime"

	"github.com/karalef/quark/internal"
	"golang.org/x/crypto/argon2"
)

// passphrased consts
const (
	PassphrasedSaltSize = 32
	PassphrasedIVSize   = aes.BlockSize
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

// PassphrasedOpts represents options for Passphrased.
type PassphrasedOpts struct {
	Rand   io.Reader // used to generate salt and IV
	Salt   []byte    // if nil, will be generated using rand or crypto/rand
	IV     []byte    // if nil, will be generated using rand or crypto/rand
	Argon2 Argon2Opts
}

func newPasspharsed(passphrase string, salt, iv []byte, opts Argon2Opts) cipher.Stream {
	if len(passphrase) == 0 {
		panic("empty passphrase")
	}
	if len(salt) != PassphrasedSaltSize {
		panic("invalid salt size")
	}
	if len(iv) != PassphrasedIVSize {
		panic("invalid iv size")
	}

	if opts == (Argon2Opts{}) {
		opts = Argon2Default
	}
	if opts.Time == 0 {
		opts.Time = 1 // draft RFC recommended value
	}
	if opts.Memory == 0 {
		opts.Memory = 64 * 1024 // draft RFC recommended value
	}
	if opts.Threads == 0 {
		opts.Threads = uint8(runtime.GOMAXPROCS(0))
	}

	// derive aes256 key in one pass with 64MiB memory cost on 4 threads.
	key := argon2.IDKey([]byte(passphrase), salt, opts.Time, opts.Memory, opts.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // must never happen
	}

	return cipher.NewCTR(block, iv)
}

// Passphrased returns a writer encrypted with provided passphrase.
// It panics if the provided salt or iv sizes are not equal to PassphrasedSaltSize and PassphrasedIVSize.
func Passphrased(w io.Writer, passphrase string, opts ...PassphrasedOpts) (io.Writer, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}

	var o PassphrasedOpts
	if len(opts) > 0 {
		o = opts[0]
	}

	var err error

	if o.Salt == nil {
		o.Salt, err = internal.RandRead(o.Rand, PassphrasedSaltSize)
		if err != nil {
			return nil, err
		}
	}
	if o.IV == nil {
		o.IV, err = internal.RandRead(o.Rand, PassphrasedIVSize)
		if err != nil {
			return nil, err
		}
	}

	stream := newPasspharsed(passphrase, o.Salt, o.IV, o.Argon2)

	// write header
	err = internal.WriteFull(w, o.Salt)
	if err != nil {
		return nil, err
	}
	err = internal.WriteFull(w, o.IV)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// PassphrasedDecrypter returns a reader decrypted with provided passphrase.
func PassphrasedDecrypter(r io.Reader, passphrase string, opts ...Argon2Opts) (io.Reader, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}

	// read header
	saltIV := make([]byte, PassphrasedSaltSize+PassphrasedIVSize)
	if _, err := io.ReadFull(r, saltIV); err != nil {
		return nil, err
	}

	var o Argon2Opts
	if len(opts) > 0 {
		o = opts[0]
	}

	return &cipher.StreamReader{
		S: newPasspharsed(passphrase, saltIV[:PassphrasedSaltSize], saltIV[PassphrasedSaltSize:], o),
		R: r,
	}, nil
}
