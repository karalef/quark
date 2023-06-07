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
		if opt != nil {
			opt.apply(&o)
		}
	}

	object, pipeW := io.Pipe()
	p := &Packet{
		Tag:    tag,
		Object: Stream{Reader: object},
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
	return passphraseOpt(passphrase)
}

// WithDecompressionOpts decompresses a packet using provided options.
func WithDecompressionOpts(opts map[Compression]DecompressOpts) UnpackOption {
	return decompressOpt(opts)
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

type decompressOpt map[Compression]DecompressOpts

func (o decompressOpt) apply(opts *unpackOptions) { opts.decompress = o }

type unpackOptions struct {
	passphrase passphraseOpt
	decompress decompressOpt
}

// DecodePacket decodes the binary formatted packet.
// Returns the decoded packet even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*Packet, error) {
	p, err := DecodeBinaryNew[Packet](in)
	if err != nil {
		return p, err
	}

	_, err = p.Tag.Type()
	return p, err
}

// UnpackPacket unpacks the binary formatted object from the packet.
// Returns a RawObject (with ErrUnknownTag error) if the tag is unknown.
func UnpackPacket(p *Packet, opts ...UnpackOption) (Packable, error) {
	if p == nil {
		return nil, nil
	}

	var o unpackOptions
	for _, opt := range opts {
		if opt != nil {
			opt.apply(&o)
		}
	}

	reader := p.Object.Reader
	var err error
	if p.IsEncrypted() {
		reader, err = o.passphrase.reader(reader, p.Header.Encryption)
		if err != nil {
			return nil, err
		}
	}

	if p.IsCompressed() {
		comp := p.Header.Compression
		reader, err = Decompress(reader, comp, o.decompress[comp])
		if err != nil {
			return nil, err
		}
	}

	typ, err := p.Tag.Type()
	if err != nil {
		return &RawObject{
			Tag:    p.Tag,
			Stream: Stream{Reader: reader},
		}, err
	}

	v := typ.new()
	decErr := DecodeBinary(reader, v)
	if decErr != nil {
		return nil, decErr
	}
	return v, err
}

// Unpack decodes the packet and unpacks the binary formatted object.
// Returns a RawObject (with ErrUnknownTag error) if the tag is unknown.
func Unpack(in io.Reader, opts ...UnpackOption) (Tag, Packable, error) {
	p, err := DecodePacket(in)
	if err != nil && err != ErrUnknownTag {
		return TagInvalid, nil, err
	}

	v, err := UnpackPacket(p, opts...)
	return p.Tag, v, err
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
