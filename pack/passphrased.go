package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

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

func newPasspharsed(passphrase string, salt, iv []byte) (cipher.Stream, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}
	if len(salt) != PassphrasedSaltSize {
		panic("invalid salt size")
	}
	if len(iv) != PassphrasedIVSize {
		panic("invalid iv size")
	}

	// derive aes256 key in one pass with 64MiB memory cost on 4 threads.
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // must never happen
	}

	return cipher.NewCTR(block, iv), nil
}

// Passphrased returns a writer encrypted with provided passphrase.
func Passphrased(w io.Writer, passphrase string, rand io.Reader) (io.Writer, error) {
	saltIV, err := internal.RandRead(rand, PassphrasedSaltSize+PassphrasedIVSize)
	if err != nil {
		return nil, err
	}
	return PassphrasedOpts(w, passphrase, saltIV[:PassphrasedSaltSize], saltIV[PassphrasedSaltSize:])
}

// PassphrasedOpts returns a writer encrypted with provided passphrase.
// It panics if the provided salt or iv sizes are not equal to PassphrasedSaltSize and PassphrasedIVSize.
func PassphrasedOpts(w io.Writer, passphrase string, salt, iv []byte) (io.Writer, error) {
	stream, err := newPasspharsed(passphrase, salt, iv)
	if err != nil {
		return nil, err
	}

	// write header
	err = internal.WriteFull(w, salt)
	if err != nil {
		return nil, err
	}
	err = internal.WriteFull(w, iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// PassphrasedDecrypter returns a reader decrypted with provided passphrase.
func PassphrasedDecrypter(r io.Reader, passphrase string) (io.Reader, error) {
	// read header
	saltIV := make([]byte, PassphrasedSaltSize+PassphrasedIVSize)
	if _, err := io.ReadFull(r, saltIV); err != nil {
		return nil, err
	}

	stream, err := newPasspharsed(passphrase, saltIV[:PassphrasedSaltSize], saltIV[PassphrasedSaltSize:])
	if err != nil {
		return nil, err
	}

	return &cipher.StreamReader{S: stream, R: r}, nil
}
