package pack

import (
	"encoding/gob"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

// Pack encodes an object into binary format.
func Pack(out io.Writer, v any) error {
	return gob.NewEncoder(out).Encode(v)
}

// Unpack decodes an object from binary format.
func Unpack(in io.Reader, v any) error {
	return gob.NewDecoder(in).Decode(v)
}

// Armored encodes an object into binary format with an OpenPGP armor.
func Armored(out io.Writer, v any, blockType string, h map[string]string) error {
	wc, err := ArmoredEncoder(out, blockType, h)
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

// UnpackArmored decodes an object from binary format with an OpenPGP armor.
func UnpackArmored(in io.Reader, v any, blockType ...string) (string, map[string]string, error) {
	block, err := DecodeArmored(in)
	if err != nil {
		return "", nil, err
	}

	for _, bt := range blockType {
		if block.Type == bt {
			return block.Type, block.Header, Unpack(block.Body, v)
		}
	}

	return "", nil, ErrInvalidBlockType
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
