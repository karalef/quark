package bind

import (
	"bytes"
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/pack"
)

// NewPackable returns a new binding data with value that can be msgpack encoded.
func NewPackable(v any, typ Type, md Metadata) (BindingData, error) {
	if v == nil {
		return BindingData{}, errors.New("nil value")
	}
	b := bytes.NewBuffer(nil)
	err := pack.EncodeBinary(b, v)
	if err != nil {
		return BindingData{}, err
	}
	return BindingData{
		Type:     typ,
		Metadata: md,
		Data:     b.Bytes(),
	}, nil
}

// Packable binds a msgpack encodable value to the identity.
func Packable(id *quark.Identity, sk quark.PrivateKey, typ Type, md Metadata, data any, expires int64) (Binding, error) {
	bd, err := NewPackable(data, typ, md)
	if err != nil {
		return Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

// DecodePackable decodes a msgpack encoded value from Binding.
func DecodePackable[T any](b Binding) (*T, error) {
	return pack.DecodeBinaryNew[T](bytes.NewReader(b.Data))
}
