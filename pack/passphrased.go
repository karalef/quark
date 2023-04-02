package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/karalef/quark/internal"
	"golang.org/x/crypto/argon2"
)

const (
	PassphrasedSaltSize = 32
	PassphrasedIVSize   = aes.BlockSize
)

var (
	ErrInvalidPassphrase = errors.New("invalid passphrase")
)

func Passphrased(w io.Writer, passphrase string, rand io.Reader) (io.Writer, error) {
	salt, err := internal.RandRead(rand, PassphrasedSaltSize)
	if err != nil {
		return nil, err
	}
	iv, err := internal.RandRead(rand, PassphrasedIVSize)
	if err != nil {
		return nil, err
	}
	return PassphrasedOpts(w, passphrase, salt, iv)
}

func PassphrasedOpts(w io.Writer, passphrase string, salt, iv []byte) (io.Writer, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}
	if len(salt) != PassphrasedSaltSize {
		panic("invalid salt size")
	}
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32) // aes256

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(iv) != block.BlockSize() {
		panic("invalid iv size")
	}

	// write header
	_, err = w.Write(salt)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{S: cipher.NewCTR(block, iv), W: w}, nil
}

func PassphrasedDecoder(r io.Reader, passphrase string) (io.Reader, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}

	// read header
	salt := make([]byte, PassphrasedSaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32) // aes256

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: r}, nil
}
