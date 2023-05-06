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
type Option interface {
	apply(*options)
}

// WithCompression compresses a packet.
func WithCompression(alg Compression, lvl int) Option {
	return &compressOpt{
		alg: alg,
		lvl: lvl,
	}
}

// WithEncryption encrypts a packet.
// If params is nil, random values are used.
func WithEncryption(passphrase string, params *Encryption) Option {
	if params == nil {
		params = new(Encryption)
		params.IV = [IVSize]byte(internal.Rand(IVSize))
		params.Salt = internal.Rand(SaltSizeRFC)
		params.Argon2ID = Argon2Defaults()
	}
	return &encryptOpt{
		passphrase: passphrase,
		params:     *params,
	}
}

type compressOpt struct {
	alg Compression
	lvl int
}

func (o *compressOpt) apply(opts *options) { opts.compress = o }

type encryptOpt struct {
	passphrase string
	params     Encryption
}

func (o *encryptOpt) writer(w io.Writer) io.WriteCloser {
	return NopCloser(Encrypt(w, o.passphrase, o.params.IV, o.params.Salt, o.params.Argon2ID))
}

func (o *encryptOpt) apply(opts *options) { opts.enc = o }

type options struct {
	compress *compressOpt

	enc *encryptOpt
}

// Pack creates a packet and encodes it into binary format.
func Pack(out io.Writer, v Packable, opts ...Option) error {
	object, pipeW := io.Pipe()
	p := &Packet{
		Tag:    v.PacketTag(),
		Object: object,
	}

	var o options
	for _, opt := range opts {
		opt.apply(&o)
	}

	writer := io.WriteCloser(pipeW)

	if o.enc != nil {
		p.Header.Encryption = &o.enc.params
		writer = ChainCloser(writer, o.enc.writer(writer))
	}

	if o.compress != nil {
		p.Header.Compression = o.compress.alg
		w, err := Compress(writer, o.compress.alg, o.compress.lvl)
		if err != nil {
			return err
		}
		writer = ChainCloser(writer, w)
	}

	go func() {
		err := EncodeBinary(writer, v)
		if err == nil {
			err = writer.Close()
		}
		pipeW.CloseWithError(err)
	}()

	return EncodeBinary(out, p)
}

// UnpackOption represents unpacking option.
type UnpackOption interface {
	apply(*unpackOptions)
}

// WithPassphrase decrypts a packet if it is encrypted.
// passphrase func called only if the packet is encrypted.
// Panics if passphrase is nil.
func WithPassphrase(passphrase func() (string, error)) UnpackOption {
	if passphrase == nil {
		panic("nil passphrase")
	}
	return passphraseOpt(passphrase)
}

type passphraseOpt func() (string, error)

var errNoPassphrase = errors.New("pack: object is encrypted but no passphrase is provided")

func (o passphraseOpt) reader(r io.Reader, enc *Encryption) (io.Reader, error) {
	if o == nil {
		return nil, errNoPassphrase
	}
	pass, err := o()
	if err != nil {
		return nil, errors.Join(errNoPassphrase, err)
	}
	return Decrypt(r, pass, enc.IV, enc.Salt, enc.Argon2ID), nil
}

func (o passphraseOpt) apply(opts *unpackOptions) { opts.passphrase = o }

type unpackOptions struct {
	passphrase passphraseOpt
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

	var o unpackOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	reader := p.Object

	if enc := p.Header.Encryption; enc != nil {
		reader, err = o.passphrase.reader(reader, enc)
		if err != nil {
			return p.Tag, nil, err
		}
	}

	if comp := p.Header.Compression; comp != NoCompression {
		reader, err = Decompress(reader, comp)
		if err != nil {
			return p.Tag, nil, err
		}
	}

	v := typ.new()
	return p.Tag, v, DecodeBinary(reader, v)
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
