package pack

import (
	"io"

	"github.com/karalef/quark"
)

// File packs a file into an binary format.
func File(out io.Writer, file *quark.File) error {
	return Pack(out, file)
}

// UnpackFile unpacks a file object in binary format.
func UnpackFile(in io.Reader) (*quark.File, error) {
	file := new(quark.File)
	err := Unpack(in, file)
	if err != nil {
		return nil, err
	}
	return file, nil
}
