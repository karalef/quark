package encrypted

import (
	"strings"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack"
)

// XOF wraps a XOF algorithm to be msgpack de/encodable.
type XOF struct {
	xof.Scheme
}

// EncodeMsgpack implements pack.CustomEncoder.
func (x XOF) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(strings.ToUpper(x.Name()))
}

// DecodeMsgpack implements pack.CustomDecoder.
func (x *XOF) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	x.Scheme, err = xof.ByName(str)
	return err
}

var _ pack.CustomEncoder = KDF{}
var _ pack.CustomDecoder = (*KDF)(nil)

// KDF wraps an KDF scheme to be msgpack de/encodable.
type KDF struct {
	kdf.Scheme
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s KDF) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.Name())
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *KDF) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	s.Scheme, err = kdf.ByName(str)
	return err
}

var _ pack.CustomEncoder = Scheme{}
var _ pack.CustomDecoder = (*Scheme)(nil)

// Scheme wraps an AEAD encryption scheme to be msgpack de/encodable.
type Scheme struct {
	aead.Scheme
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s Scheme) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.Name())
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *Scheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	s.Scheme, err = aead.FromName(str)
	return err
}
