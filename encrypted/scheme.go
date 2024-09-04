package encrypted

import (
	"strings"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/pack"
)

var _ pack.CustomEncoder = (*XOF)(nil)
var _ pack.CustomDecoder = (*XOF)(nil)

// XOF wraps a XOF algorithm to be msgpack de/encodable.
type XOF struct {
	xof.XOF
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
	x.XOF = xof.ByName(str)
	if x.XOF == nil {
		err = ErrInvalidScheme
	}
	return nil
}

// Password contains password-based encryption parameters.
type Password struct {
	KDF  KDFScheme `msgpack:"kdf"`
	Cost kdf.Cost  `msgpack:"cost"`
	Salt []byte    `msgpack:"salt"`
}

var _ pack.CustomEncoder = KDFScheme{}
var _ pack.CustomDecoder = (*KDFScheme)(nil)

// KDFScheme wraps an KDF scheme to be msgpack de/encodable.
type KDFScheme struct {
	kdf.Scheme
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s KDFScheme) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.Name())
}

// Parse parses a symmetric encryption scheme.
func (s *KDFScheme) Parse(str string) error {
	s.Scheme = kdf.ByName(str)
	if s.Scheme == nil {
		return ErrInvalidScheme
	}
	return nil
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *KDFScheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	return s.Parse(str)
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

// Parse parses a symmetric encryption scheme.
func (s *Scheme) Parse(str string) error {
	scheme := internal.SplitSchemeName(str)
	if len(scheme) != 2 {
		return ErrInvalidScheme
	}

	cipher := cipher.ByName(scheme[0])
	mac := mac.ByName(scheme[1])
	if cipher == nil || mac == nil {
		return ErrInvalidScheme
	}
	s.Scheme = aead.Build(cipher, mac)
	return nil
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *Scheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	return s.Parse(str)
}
