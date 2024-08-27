package bind

import (
	"bytes"
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// well-known bind types
const (
	TypeGroupQuarkKey Type = quark.BindTypeGroupQuark + ".key"
	TypeSignKey       Type = TypeGroupQuarkKey + ".sign"
	TypeKEMKey        Type = TypeGroupQuarkKey + ".kem"
)

// NewKey returns a new key binding data.
func NewKey(key sign.PublicKey, md Metadata) (BindingData, error) {
	if key == nil {
		return BindingData{}, errors.New("nil key")
	}
	return newKey(quark.KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}, TypeSignKey, md)
}

// NewKEM returns a new KEM key binding data.
func NewKEM(key kem.PublicKey, md Metadata) (BindingData, error) {
	if key == nil {
		return BindingData{}, errors.New("nil key")
	}
	return newKey(quark.KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}, TypeKEMKey, md)
}

func newKey(m quark.KeyModel, typ Type, md Metadata) (BindingData, error) {
	b := bytes.NewBuffer(nil)
	err := pack.EncodeBinary(b, m)
	if err != nil {
		return BindingData{}, err
	}

	return BindingData{
		Type:     typ,
		Metadata: md,
		Data:     b.Bytes(),
	}, nil
}

// Key binds a key to the identity.
func Key(id *quark.Identity, sk sign.PrivateKey, md Metadata, key sign.PublicKey, expires int64) (Binding, error) {
	bd, err := NewKey(key, md)
	if err != nil {
		return Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

// KEM binds a KEM key to the identity.
func KEM(id *quark.Identity, sk sign.PrivateKey, md Metadata, key kem.PublicKey, expires int64) (Binding, error) {
	bd, err := NewKEM(key, md)
	if err != nil {
		return Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

func decodeKey(b Binding, typ Type) (*quark.KeyModel, error) {
	if b.Type != typ {
		return nil, errors.New("invalid type")
	}
	return pack.DecodeBinaryNew[quark.KeyModel](bytes.NewReader(b.Data))
}

// DecodeKey decodes a key from the binding.
func DecodeKey(b Binding) (sign.PublicKey, error) {
	m, err := decodeKey(b, TypeSignKey)
	if err != nil {
		return nil, err
	}
	scheme := sign.ByName(m.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown scheme")
	}
	return scheme.UnpackPublic(m.Key)
}

// DecodeKEM decodes a KEM key from the binding.
func DecodeKEM(b Binding) (kem.PublicKey, error) {
	m, err := decodeKey(b, TypeKEMKey)
	if err != nil {
		return nil, err
	}
	scheme := kem.ByName(m.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown scheme")
	}
	return scheme.UnpackPublic(m.Key)
}
