package pack

import (
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/karalef/quark/internal"
)

// Option represents packing option.
type Option interface {
	apply(*options)
}

// WithArmor makes the output OpenPGP armored.
func WithArmor(header map[string]string) Option {
	return &armorOpt{
		header: header,
	}
}

// WithCompression compresses a packet.
func WithCompression(c Compressor) Option {
	if c == nil {
		c = nopCompressor{}
	}
	return &compressOpt{c}
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

type armorOpt struct {
	header map[string]string
}

func (o *armorOpt) apply(opts *options) { opts.armor = o }

type compressOpt struct {
	Compressor
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
	armor *armorOpt

	compress *compressOpt
	enc      *encryptOpt
}

// Pack creates a packet and encodes it into binary format.
func Pack(out io.Writer, v Packable, opts ...Option) error {
	tag := v.PacketTag()
	if _, err := tag.Type(); err != nil {
		return err
	}

	var o options
	for _, opt := range opts {
		opt.apply(&o)
	}

	var output io.WriteCloser

	if o.armor != nil {
		var err error
		output, err = ArmoredEncoder(out, tag.BlockType(), o.armor.header)
		if err != nil {
			return err
		}
	} else {
		output = NopCloser(out)
	}

	object, pipeW := io.Pipe()
	p := &Packet{
		Tag:    tag,
		Object: Object{Reader: object},
	}

	writer := io.WriteCloser(pipeW)

	if o.enc != nil {
		p.Header.Encryption = &o.enc.params
		writer = ChainCloser(writer, o.enc.writer(writer))
	}

	if o.compress != nil {
		p.Header.Compression = o.compress.Algorithm()
		w, err := Compress(writer, o.compress.Compressor)
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

	err := EncodeBinary(output, p)
	if err != nil {
		return err
	}

	return output.Close()
}

// UnpackOption represents unpacking option.
type UnpackOption interface {
	apply(*unpackOptions)
}

// WithoutArmor skips OpenPGP armor determination.
func WithoutArmor() UnpackOption {
	return withoutArmor{}
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

// WithDecompressionOpts decompresses a packet using provided options.
func WithDecompressionOpts(opts map[Compression]DecompressOpts) UnpackOption {
	return decompressOpt(opts)
}

type withoutArmor struct{}

func (withoutArmor) apply(opts *unpackOptions) { opts.noArmor = true }

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

type decompressOpt map[Compression]DecompressOpts

func (o decompressOpt) apply(opts *unpackOptions) { opts.decompress = o }

type unpackOptions struct {
	noArmor bool

	passphrase passphraseOpt
	decompress decompressOpt
}

// Unpack unpacks an object from binary format.
func Unpack(in io.Reader, opts ...UnpackOption) (Tag, Packable, error) {
	var o unpackOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	if !o.noArmor {
		_, _, r, err := Dearmor(in)
		if err != nil {
			return TagInvalid, nil, err
		}
		in = r
	}

	p, err := DecodeBinaryNew[Packet](in)
	if err != nil {
		return TagInvalid, nil, err
	}

	typ, err := p.Tag.Type()
	if err != nil {
		return p.Tag, nil, err
	}
	reader := p.Object.Reader

	if enc := p.Header.Encryption; enc != nil {
		reader, err = o.passphrase.reader(reader, enc)
		if err != nil {
			return p.Tag, nil, err
		}
	}

	if comp := p.Header.Compression; comp != NoCompression {
		reader, err = Decompress(reader, comp, o.decompress[p.Header.Compression])
		if err != nil {
			return p.Tag, nil, err
		}
	}

	v := typ.new()
	return p.Tag, v, DecodeBinary(reader, v)
}

// ErrMismatchType is returned when the object type mismatches the expected one.
type ErrMismatchType struct {
	expected Packable
	got      Tag
}

func (e ErrMismatchType) Error() string {
	if reflect.TypeOf(e.expected) == nil { // type parameter is interface
		return fmt.Sprintf("object type (%s) does not implement the specified interface", e.got.String())
	}
	return fmt.Sprintf("object type mismatches the expected %s (got %s)", e.expected.PacketTag().String(), e.got.String())
}

// UnpackExact decodes an object from binary format and casts it to specified type.
func UnpackExact[T Packable](in io.Reader, opts ...UnpackOption) (val T, err error) {
	tag, v, err := Unpack(in, opts...)
	if err != nil {
		return
	}
	val, ok := v.(T)
	if !ok {
		return val, ErrMismatchType{expected: val, got: tag}
	}
	return
}
