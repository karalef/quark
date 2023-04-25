package pack

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/openpgp/armor"
)

// Packable reprsents a packable object.
type Packable interface {
	Type() MsgType
}

// Pack encodes an object into binary format.
func Pack(out io.Writer, v Packable) error {
	return msgpack.NewEncoder(out).Encode(struct {
		Tag   Tag      `msgpack:"tag"`
		Block Packable `msgpack:"block"`
	}{
		Tag:   v.Type().Tag,
		Block: v,
	})
}

// Unpack decodes an object from binary format.
func Unpack(in io.Reader) (Tag, any, error) {
	var block struct {
		Tag   Tag                `msgpack:"tag"`
		Block msgpack.RawMessage `msgpack:"block"`
	}
	err := msgpack.NewDecoder(in).Decode(&block)
	if err != nil {
		return TagInvalid, nil, err
	}

	unp, err := block.Tag.Unpacker()
	if err != nil {
		return block.Tag, nil, err
	}

	v, err := unp(bytes.NewReader(block.Block))
	return block.Tag, v, err
}

func unpack[T any](in io.Reader) (v *T, err error) {
	v = new(T)
	return v, msgpack.NewDecoder(in).Decode(v)
}

// ErrMismatchTag is returned when the message tag mismatches the expected tag.
type ErrMismatchTag struct {
	expected, got Tag
}

func (e ErrMismatchTag) Error() string {
	return fmt.Sprintf("message tag mismatches the expected %s (got %s)", e.expected.String(), e.got.String())
}

// DecodeExact decodes an object from binary format with specified tag and type.
// Returns ErrMismatchTag if the message tag mismatches the expected tag.
// It panics if the type parameter mismatches the type of unpacked object.
func DecodeExact[T any](in io.Reader, tag Tag) (v T, err error) {
	t, val, err := Decode(in)
	if err != nil {
		return
	}
	if t != tag {
		return v, ErrMismatchTag{expected: tag, got: t}
	}

	v, ok := val.(T)
	if !ok {
		panic("type parameter mismatches the type of unpacked object")
	}
	return
}

// ErrMismatchBlockType is returned when the message tag mismatches the armor block type.
var ErrMismatchBlockType = errors.New("message tag mssmatches the block type")

// Decode decodes an object from binary format.
// It can automaticaly determine armor encoding.
// It returns ErrMismatchBlockType if the block type mismatches the tag.
func Decode(in io.Reader) (Tag, any, error) {
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

const armorStart = "-----BEGIN "

// DetermineArmor determines if an input is an OpenPGP armored block.
// It returns multireader with peeked data.
func DetermineArmor(in io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, len(armorStart))
	n, err := io.ReadFull(in, buf)
	return string(buf) == armorStart, io.MultiReader(bytes.NewReader(buf[:n]), in), err
}

// Armored encodes an object into binary format with an OpenPGP armor.
func Armored(out io.Writer, v Packable, h map[string]string) error {
	wc, err := ArmoredEncoder(out, v.Type().BlockType, h)
	if err != nil {
		return err
	}

	err = Pack(wc, v)
	if err != nil {
		wc.Close()
		return err
	}

	return wc.Close()
}

// ArmoredBlock represents an OpenPGP armored block.
type ArmoredBlock = armor.Block

// ArmoredEncoder returns an OpenPGP armored encoder.
func ArmoredEncoder(out io.Writer, blockType string, headers map[string]string) (io.WriteCloser, error) {
	return armor.Encode(out, blockType, headers)
}

// DecodeArmored decodes an OpenPGP armored block.
func DecodeArmored(in io.Reader) (*ArmoredBlock, error) {
	return armor.Decode(in)
}
