package binary

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

// Raw is an alias for msgpack.RawMessage.
type Raw = msgpack.RawMessage

// GetEncoder gets the encoder from the pool.
func GetEncoder(w io.Writer) *Encoder {
	enc := msgpack.GetEncoder()
	enc.Reset(w)
	return enc
}

// GetDecoder gets the decoder from the pool.
func GetDecoder(in io.Reader) *Decoder {
	dec := msgpack.GetDecoder()
	dec.Reset(in)
	return dec
}

// PutEncoder puts the encoder to the pool.
func PutEncoder(enc *Encoder) { msgpack.PutEncoder(enc) }

// PutDecoder puts the decoder to the pool.
func PutDecoder(dec *Decoder) { msgpack.PutDecoder(dec) }

// Encode encodes an object into binary MessagePack format.
func Encode(w io.Writer, v any) error {
	enc := GetEncoder(w)
	defer PutEncoder(enc)
	return enc.Encode(v)
}

// Decode decodes an object from binary MessagePack format.
func Decode(r io.Reader, v any) error {
	dec := GetDecoder(r)
	defer PutDecoder(dec)
	return dec.Decode(v)
}

// EncodeBytes encodes an object into binary MessagePack format.
func EncodeBytes(v any) ([]byte, error) { return msgpack.Marshal(v) }

// DecodeBytes decodes an object from binary MessagePack format.
func DecodeBytes(b []byte, v any) error { return msgpack.Unmarshal(b, v) }

// DecodeNew allocates and decodes an object from binary MessagePack format.
func DecodeNew[T any](r io.Reader) (*T, error) {
	v := new(T)
	if err := Decode(r, v); err != nil {
		return nil, err
	}
	return v, nil
}
