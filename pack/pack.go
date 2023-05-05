package pack

import (
	"errors"
	"fmt"
	"io"

	"github.com/karalef/quark/internal"
)

// Packable represents a packable object.
type Packable interface {
	PacketTag() Tag
}

// Option represents packing option.
type Option func(*Packet, io.Writer) io.Writer

// WithEncryption encrypt a packet.
// If params is nil, random values are used.
func WithEncryption(passphrase string, params *EncryptionParams, argon2opts ...Argon2Opts) Option {
	if params == nil {
		params = new(EncryptionParams)
		params.IV = [IVSize]byte(internal.Rand(IVSize))
		params.Salt = [SaltSize]byte(internal.Rand(SaltSize))
	}
	return func(p *Packet, w io.Writer) io.Writer {
		p.Header.Encryption = params
		return Encrypt(w, passphrase, params.IV[:], params.Salt[:], argon2opts...)
	}
}

// Pack creates a packet and encodes it into binary format.
func Pack(out io.Writer, v Packable, opts ...Option) error {
	object, pipeW := io.Pipe()
	p := &Packet{
		Tag:    v.PacketTag(),
		Object: object,
	}

	w := io.Writer(pipeW)
	for _, o := range opts {
		w = o(p, w)
	}

	go func() {
		pipeW.CloseWithError(EncodeBinary(w, v))
	}()

	return EncodeBinary(out, p)
}

// UnpackOption represents unpacking option.
type UnpackOption func(*Packet) error

// WithPassphrase decrypts a packet if it is encrypted.
// passphrase func called only if the packet is encrypted.
func WithPassphrase(passphrase func() (string, error), argon2opts ...Argon2Opts) UnpackOption {
	return func(p *Packet) error {
		enc := p.Header.Encryption
		if enc == nil {
			return nil
		}
		if passphrase == nil {
			return errors.New("object is encrypted but no options are provided")
		}
		pass, err := passphrase()
		if err != nil {
			return err
		}
		p.Object = Decrypt(p.Object, pass, enc.IV[:], enc.Salt[:], argon2opts...)
		return nil
	}
}

// Unpack unpacks an object from binary format.
func Unpack(in io.Reader, opts ...UnpackOption) (Tag, Packable, error) {
	p, err := DecodeBinaryNew[Packet](in)
	if err != nil {
		return TagInvalid, nil, err
	}

	typ, err := p.Tag.Type()
	if err != nil {
		return p.Tag, nil, err
	}

	for _, o := range opts {
		if err = o(p); err != nil {
			return p.Tag, nil, err
		}
	}

	v := typ.new()
	return p.Tag, v, DecodeBinary(p.Object, v)
}

// ErrMismatchTag is returned when the message tag mismatches the expected tag.
type ErrMismatchTag struct {
	expected, got Tag
}

func (e ErrMismatchTag) Error() string {
	return fmt.Sprintf("message tag mismatches the expected %s (got %s)", e.expected.String(), e.got.String())
}

// UnpackExact decodes an object from binary format with specified type.
func UnpackExact[T Packable](in io.Reader, opts ...UnpackOption) (val T, err error) {
	tag, v, err := Unpack(in, opts...)
	if err != nil {
		return
	}
	if tag != val.PacketTag() {
		return val, ErrMismatchTag{expected: val.PacketTag(), got: tag}
	}
	return v.(T), nil
}

// DecodeExact decodes an object from binary format with specified tag and type.
// Returns ErrMismatchTag if the message tag mismatches the expected tag.
// It panics if the type parameter mismatches the type of unpacked object.
func DecodeExact[T Packable](in io.Reader) (v T, err error) {
	t, val, err := Decode(in)
	if err != nil {
		return
	}
	if t != v.PacketTag() {
		return v, ErrMismatchTag{expected: v.PacketTag(), got: t}
	}

	v, ok := val.(T)
	if !ok {
		panic("type parameter mismatches the type of unpacked object")
	}
	return
}

// ErrMismatchBlockType is returned when the message tag mismatches the armor block type.
var ErrMismatchBlockType = errors.New("message tag mismatches the block type")

// Decode decodes an object from binary format.
// It can automatically determine armor encoding.
// It returns ErrMismatchBlockType if the block type mismatches the tag.
func Decode(in io.Reader) (Tag, Packable, error) {
	armor, in, err := DetermineArmor(in)
	if err != nil {
		return TagInvalid, nil, err
	}

	if !armor {
		return Unpack(in)
	}

	block, err := DecodeArmored(in)
	if err != nil {
		return TagInvalid, nil, err
	}

	tag, v, err := Unpack(block.Body)
	if err != nil {
		return tag, v, err
	}

	if tag.String() != block.Type {
		return tag, v, ErrMismatchBlockType
	}

	return tag, v, nil
}
