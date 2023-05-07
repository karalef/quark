package pack

import (
	"errors"
	"fmt"
	"io"

	"github.com/karalef/quark/internal"
	"github.com/vmihailenco/msgpack/v5"
)

// Packable represents a packable object.
type Packable interface {
	PacketTag() Tag
}

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

type armorOpt struct {
	header map[string]string
}

func (o *armorOpt) apply(opts *options) { opts.armor = o }

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
	armor    *armorOpt
	compress *compressOpt

	enc *encryptOpt
}

// Pack creates a packet and encodes it into binary format.
func Pack(out io.Writer, v Packable, opts ...Option) error {
	var o options
	for _, opt := range opts {
		opt.apply(&o)
	}

	output := NopCloser(out)

	if o.armor != nil {
		var err error
		output, err = ArmoredEncoder(output, v.PacketTag().BlockType(), o.armor.header)
		if err != nil {
			return err
		}
	}

	object, pipeW := io.Pipe()
	p := &Packet{
		Tag:    v.PacketTag(),
		Object: object,
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

type unpackOptions struct {
	passphrase passphraseOpt
	noArmor    bool
}

// Unpack unpacks an object from binary format.
func Unpack(in io.Reader, opts ...UnpackOption) (Tag, Packable, error) {
	var o unpackOptions
	for _, opt := range opts {
		opt.apply(&o)
	}

	if !o.noArmor {
		armored, r, err := DetermineArmor(in)
		if err != nil {
			return TagInvalid, nil, err
		}
		in = r
		if armored {
			block, err := DecodeArmored(r)
			if err != nil {
				return TagInvalid, nil, err
			}
			in = block.Body
		}
	}

	p, err := DecodeBinaryNew[Packet](in)
	if err != nil {
		return TagInvalid, nil, err
	}

	typ, err := p.Tag.Type()
	if err != nil {
		return p.Tag, nil, err
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

// Packet is a binary packet.
type Packet struct {
	Tag    Tag
	Header struct {
		Encryption  *Encryption `msgpack:"encryption,omitempty"`
		Compression Compression `msgpack:"compression,omitempty"`
	}
	Object io.Reader
}

// EncodeMsgpack implements msgpack.CustomEncoder.
func (p *Packet) EncodeMsgpack(enc *msgpack.Encoder) error {
	err := enc.EncodeUint8(uint8(p.Tag))
	if err != nil {
		return err
	}
	enc.SetOmitEmpty(true)
	err = enc.Encode(p.Header)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc.Writer(), p.Object)
	return err
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (p *Packet) DecodeMsgpack(dec *msgpack.Decoder) error {
	tag, err := dec.DecodeUint8()
	if err != nil {
		return err
	}
	p.Tag = Tag(tag)
	err = dec.Decode(&p.Header)
	if err != nil {
		return err
	}

	p.Object = dec.Buffered()
	return err
}

var (
	_ msgpack.CustomEncoder = (*Packet)(nil)
	_ msgpack.CustomDecoder = (*Packet)(nil)
)
