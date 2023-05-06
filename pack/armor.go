package pack

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

const armorStart = "-----BEGIN "

// DetermineArmor determines if an input is an OpenPGP armored block.
// It returns multireader with peeked data.
func DetermineArmor(in io.Reader) (bool, io.Reader, error) {
	buf := make([]byte, len(armorStart))
	n, err := io.ReadFull(in, buf)
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	in = io.MultiReader(bytes.NewReader(buf[:n]), in)
	return string(buf[:n]) == armorStart, in, err
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
