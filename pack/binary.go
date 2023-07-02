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

// GetEncoder gets the encoder from the pool.
func GetEncoder(w io.Writer) *Encoder {
	enc := msgpack.GetEncoder()
	enc.Reset(w)
	return enc
}

// PutEncoder puts the encoder to the pool.
func PutEncoder(enc *Encoder) {
	msgpack.PutEncoder(enc)
}

// GetDecoder gets the decoder from the pool.
func GetDecoder(in io.Reader) *Decoder {
	dec := msgpack.GetDecoder()
	dec.Reset(in)
	return dec
}

// PutDecoder puts the decoder to the pool.
func PutDecoder(dec *Decoder) {
	msgpack.PutDecoder(dec)
}

// EncodeBinary encodes an object into binary MessagePack format.
func EncodeBinary(w io.Writer, v any) error {
	enc := GetEncoder(w)
	defer PutEncoder(enc)
	return enc.Encode(v)
}

// DecodeBinary decodes an object from binary MessagePack format.
func DecodeBinary(r io.Reader, v any) error {
	dec := GetDecoder(r)
	defer PutDecoder(dec)
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
