package pack

import (
	"bytes"
	"errors"
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

// armor errors
var (
	ErrInvalidBlockType = errors.New("invalid block type")
)

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
