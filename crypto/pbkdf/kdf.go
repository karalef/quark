package pbkdf

import (
	"github.com/karalef/quark/pack/binary"
	"github.com/karalef/quark/scheme"
)

// KDF combines pbkdf scheme and cost.
type KDF struct {
	Scheme Scheme `msgpack:"scheme"`
	Cost   Cost   `msgpack:"cost"`
}

// Derive derives a key of the specified size from a passphrase and salt.
func (k KDF) Derive(passphrase, salt []byte, length uint32) ([]byte, error) {
	pbkdf, err := k.Scheme.New(k.Cost)
	if err != nil {
		return nil, err
	}

	return pbkdf.Derive(passphrase, salt, length), nil
}

type pbkdfConfig[T any] struct {
	Scheme Algorithm `msgpack:"scheme"`
	Cost   T         `msgpack:"cost"`
}

// EncodeMsgpack implements binary.CustomEncoder.
func (k KDF) EncodeMsgpack(enc *binary.Encoder) error {
	return enc.Encode(pbkdfConfig[Cost]{
		Scheme: scheme.NewAlgorithm[Scheme, Registry](k.Scheme),
		Cost:   k.Cost,
	})
}

// DecodeMsgpack implements binary.CustomDecoder.
func (k *KDF) DecodeMsgpack(dec *binary.Decoder) error {
	var m pbkdfConfig[binary.Raw]
	if err := dec.Decode(&m); err != nil {
		return err
	}
	k.Scheme = m.Scheme.Scheme
	k.Cost = k.Scheme.NewCost()
	return binary.DecodeBytes(m.Cost, k.Cost)
}

// Salted represents salted KDF.
type Salted struct {
	KDF  KDF    `msgpack:"kdf"`
	Salt []byte `msgpack:"salt"`
}

// Derive derives a key of the specified size from a passphrase.
func (s Salted) Derive(passphrase []byte, length uint32) ([]byte, error) {
	return s.KDF.Derive(passphrase, s.Salt, length)
}

// Fixed is a fixed-length KDF.
type Fixed struct {
	KDF KDF    `msgpack:"kdf"`
	Len uint32 `msgpack:"len"`
}

// Derive derives a key from a passphrase.
func (f Fixed) Derive(passphrase, salt []byte) ([]byte, error) {
	return f.KDF.Derive(passphrase, salt, f.Len)
}
