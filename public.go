package quark

import (
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/scheme"
)

// NewPublicKey creates a new public key.
func NewPublicKey[T crypto.Key](key T) PublicKey[T] { return PublicKey[T]{key: key} }

var (
	_ pack.Packable = (*PublicKey[crypto.Key])(nil)
	_ crypto.Key    = PublicKey[crypto.Key]{}
)

// PublicKey represents a public key as a certificate data.
type PublicKey[T crypto.Key] struct{ key T }

// PacketTag implements pack.Packable interface.
func (*PublicKey[_]) PacketTag() pack.Tag { return PacketTagPublicKey }

// Key returns the key.
func (pk PublicKey[T]) Key() T { return pk.key }

// ToKey returns an untyped public key.
func (pk PublicKey[T]) ToKey() PublicKey[crypto.Key] { return NewPublicKey[crypto.Key](pk.key) }

// ID implements crypto.Key.
func (pk PublicKey[_]) ID() crypto.ID { return pk.key.ID() }

// Fingerprint implements crypto.Key.
func (pk PublicKey[_]) Fingerprint() crypto.Fingerprint { return pk.key.Fingerprint() }

// Scheme implements crypto.Key.
func (pk PublicKey[_]) Scheme() crypto.Scheme { return pk.key.Scheme() }

// Pack implements crypto.Key.
func (pk PublicKey[_]) Pack() []byte { return pk.key.Pack() }

// SignEncode implements Signable.
func (pk PublicKey[_]) SignEncode(w io.Writer) error {
	if crypto.Key(pk.key) == nil {
		return errors.New("nil public key")
	}
	return NewKeyModel(pk.key).SignEncode(w)
}

// EncodeMsgpack implements pack.CustomEncoder.
func (pk PublicKey[_]) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(NewKeyModel(pk.key))
}

// DecodeMsgpack implements pack.CustomDecoder.
func (pk *PublicKey[T]) DecodeMsgpack(dec *pack.Decoder) error {
	m := new(KeyModel)
	err := dec.Decode(m)
	if err != nil {
		return err
	}
	var key crypto.Key
	var emtpy T
	if _, ok := crypto.Key(emtpy).(sign.PublicKey); ok {
		key, err = sign.UnpackPublic(m.Algorithm, m.Key)
	} else if _, ok := crypto.Key(emtpy).(kem.PublicKey); ok {
		key, err = kem.UnpackPublic(m.Algorithm, m.Key)
	} else if _, ok := crypto.Key(emtpy).(pke.PublicKey); ok {
		key, err = pke.UnpackPublic(m.Algorithm, m.Key)
	} else {
		key, err = sign.UnpackPublic(m.Algorithm, m.Key)
		if err == scheme.ErrUnknownScheme {
			key, err = kem.UnpackPublic(m.Algorithm, m.Key)
		}
	}
	if err == nil {
		pk.key = key.(T)
	}
	return err
}

// KeyModel returns the key model.
func NewKeyModel(key crypto.RawKey) KeyModel {
	return KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}
}

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

// SignEncode implements Signable.
func (m KeyModel) SignEncode(w io.Writer) error {
	_, err := w.Write([]byte(m.Algorithm))
	if err != nil {
		return err
	}
	_, err = w.Write(m.Key)
	return err
}
