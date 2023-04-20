package pack

import (
	"io"

	"github.com/karalef/quark"
)

// BlockTypeMessage is an armored message block type.
const BlockTypeMessage = "QUARK MESSAGE"

var typeMessage = MsgType{
	Tag:       TagMessage,
	BlockType: BlockTypeMessage,
	Unpacker:  unpackMessage,
}

var _ Packable = packedMessage{}

type packedMessage struct {
	Fingerprint quark.Fingerprint `msgpack:"fp,omitempty"`
	Signature   []byte            `msgpack:"sig,omitempty"`
	Key         []byte            `msgpack:"key,omitempty"`
	FileName    string            `msgpack:"file,omitempty"`
	Data        []byte            `msgpack:"data"`
}

func (packedMessage) Type() MsgType { return typeMessage }

// Message packs a message into binary format.
func Message(out io.Writer, msg quark.Message) error {
	return Pack(out, packedMessage{
		Fingerprint: msg.Fingerprint,
		Signature:   msg.Signature,
		Key:         msg.Key,
		FileName:    msg.File,
		Data:        msg.Data,
	})
}

func unpackMessage(in io.Reader) (any, error) {
	msg, err := unpack[packedMessage](in)
	if err != nil {
		return nil, err
	}
	return quark.Message{
		Fingerprint: msg.Fingerprint,
		Signature:   msg.Signature,
		Key:         msg.Key,
		File:        msg.FileName,
		Data:        msg.Data,
	}, nil
}
