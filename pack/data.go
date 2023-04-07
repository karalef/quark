package pack

import (
	"io"

	"github.com/karalef/quark"
)

// BlockTypeMessage is a message block type.
const BlockTypeMessage = "QUARK MESSAGE"

// Message packs a message into an OpenPGP armored block.
func Message(out io.Writer, msg *quark.Message) error {
	return Armored(out, msg, BlockTypeMessage, nil)
}

// UnpackMessage unpacks a message object in binary format with an OpenPGP armor.
func UnpackMessage(in io.Reader) (*quark.Message, error) {
	msg := new(quark.Message)
	_, _, err := UnpackArmored(in, msg, BlockTypeMessage)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

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
