package scheme

import (
	"github.com/karalef/quark/pack/binary"
)

// ByName represents a part of Registry interface with the only ByName method.
type ByName[T Scheme] interface {
	ByName(name string) (T, error)
}

// NewAlgorithm creates a new algorithm.
func NewAlgorithm[S Scheme, R ByName[S]](sch S) Algorithm[S, R] {
	return Algorithm[S, R]{Scheme: sch}
}

var _ Scheme = Algorithm[Scheme, ByName[Scheme]]{}

// Algorithm contains a scheme that can be encoded and decoded.
type Algorithm[S Scheme, R ByName[S]] struct{ Scheme S }

func (a Algorithm[_, _]) Name() string { return Normalize(a.Scheme.Name()) }

func (a Algorithm[_, _]) EncodeMsgpack(enc *binary.Encoder) error {
	return enc.EncodeString(a.Name())
}

func (a *Algorithm[_, R]) DecodeMsgpack(dec *binary.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	var reg R
	sch, err := reg.ByName(str)
	if err != nil {
		return err
	}
	a.Scheme = sch
	return nil
}
