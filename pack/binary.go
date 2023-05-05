package pack

import (
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

// CustomEncoder is an alias for msgpack.CustomEncoder.
type CustomEncoder = msgpack.CustomEncoder

// CustomDecoder is an alias for msgpack.CustomDecoder.
type CustomDecoder = msgpack.CustomDecoder

// Encoder is an alias for msgpack.Encoder.
type Encoder = msgpack.Encoder

// Decoder is an alias for msgpack.Decoder.
type Decoder = msgpack.Decoder

// EncodeBinary encodes an object into binary MessagePack format.
func EncodeBinary(w io.Writer, v any) error {
	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)

	enc.Reset(w)
	return enc.Encode(v)
}

// DecodeBinary decodes an object from binary MessagePack format.
func DecodeBinary(r io.Reader, v any) error {
	dec := msgpack.GetDecoder()
	defer msgpack.PutDecoder(dec)

	dec.Reset(r)
	return dec.Decode(v)
}

// DecodeBinaryNew allocates and decodes an object from binary MessagePack format.
func DecodeBinaryNew[T any](r io.Reader) (*T, error) {
	v := new(T)
	if err := DecodeBinary(r, v); err != nil {
		return nil, err
	}
	return v, nil
}
