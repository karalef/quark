package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
)

// passphrased consts
const (
	IVSize = aes.BlockSize

	TimeRFC     = 1         // draft RFC recommended number of rounds
	MemoryRFC   = 64 * 1024 // draft RFC recommended memory cost
	SaltSizeRFC = 16        // draft RFC recommended salt size for password hashing
)

// IV is an IV for a passphrased cipher.
type IV [IVSize]byte

// Encryption contains encryption parameters.
type Encryption struct {
	IV       IV           `msgpack:"iv"`
	Salt     []byte       `msgpack:"salt"`
	Argon2ID Argon2Params `msgpack:"argon2"`
}

// Argon2Params contains parameters for argon2id.
type Argon2Params struct {
	Time    uint32 `msgpack:"time"`    // argon2id number of rounds
	Memory  uint32 `msgpack:"memory"`  // argon2id memory cost
	Threads uint8  `msgpack:"threads"` // argon2id parallelism degree
}

// Argon2Defaults returns recommended parameters for argon2id.
func Argon2Defaults() Argon2Params {
	return Argon2Params{
		Time:    TimeRFC,
		Memory:  MemoryRFC,
		Threads: uint8(runtime.GOMAXPROCS(0)),
	}
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

// Encrypt wraps a NewPassphrased stream cipher with cipher.StreamWriter.
func Encrypt(w io.Writer, passphrase string, iv IV, salt []byte, params Argon2Params) *cipher.StreamWriter {
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
