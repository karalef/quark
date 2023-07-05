package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"runtime"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/argon2"
)

// Encrypted represents encrypted data.
type Encrypted struct {
	Compressor Compressor
	Reader     io.Reader

	Opts   map[Compression]DecompressOpts
	Writer io.Writer
}

// EncodeMsgpack encodes compressed data.
func (e *Encrypted) EncodeMsgpack(enc *msgpack.Encoder) error {
	if c == nil || c.Reader == nil {
		return enc.EncodeNil()
	}
	if c.Compressor == nil {
		c.Compressor = nopCompressor{}
	}
	err := enc.EncodeUint8(uint8(c.Compressor.Algorithm()))
	if err != nil {
		return err
	}

	sw := newStreamWriter(enc.Writer())
	_, err = io.Copy(sw, c.Reader)
	if err != nil {
		return err
	}
	return sw.Close()
}

// DecodeMsgpack decodes compressed data.
func (c *Compressed) DecodeMsgpack(dec *msgpack.Decoder) error {
	if c.Writer == nil {
		return errors.New("pack: Compressed.Writer is nil")
	}
	comp, err := dec.DecodeUint8()
	if err != nil {
		return err
	}

	decompressor, ok := decompressors[Compression(comp)]
	if !ok {
		return errors.New("pack: unknown compression algorithm")
	}
	r, err := decompressor(dec.Buffered(), c.Opts[Compression(comp)])
	if err != nil {
		return err
	}

	sr := newStreamReader(r)
	_, err = io.Copy(c.Writer, sr)
	return err
}

// Encryption contains encryption parameters.
type Encryption struct {
	IV       []byte       `msgpack:"iv"`
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
