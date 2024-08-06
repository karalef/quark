package bind

import (
	"bytes"
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encaps"
	"github.com/karalef/quark/pack"
)

// well-known bind types
const (
	TypeGroupQuarkKey Type = quark.BindTypeGroupQuark + ".key"
	TypeSignKey       Type = TypeGroupQuarkKey + ".sign"
	TypeKEMKey        Type = TypeGroupQuarkKey + ".kem"
)

// GroupKeys is the default keys group name.
const GroupKeys = "keys"

// NewKey returns a new key binding data.
// If group is empty, it will be set to GroupKeys.
func NewKey(key quark.PublicKey, group string) (BindingData, error) {
	if key == nil {
		return BindingData{}, errors.New("nil key")
	}
	return newKey(quark.KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Raw().Pack(),
	}, TypeSignKey, group)
}

// NewKEM returns a new KEM key binding data.
// If group is empty, it will be set to GroupKeys.
func NewKEM(key encaps.PublicKey, group string) (BindingData, error) {
	if key == nil {
		return BindingData{}, errors.New("nil key")
	}
	return newKey(quark.KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Raw().Pack(),
	}, TypeKEMKey, group)
}

func newKey(m quark.KeyModel, typ Type, group string) (BindingData, error) {
	if group == "" {
		group = GroupKeys
	}

	b := bytes.NewBuffer(nil)
	err := pack.EncodeBinary(b, m)
	if err != nil {
		return BindingData{}, err
	}

	return BindingData{
		Type:  typ,
		Group: group,
		Data:  b.Bytes(),
	}, nil
}

// Key binds a key to the identity.
// If group is empty, it will be set to GroupKeys.
func Key(id quark.Identity, sk quark.PrivateKey, group string, key quark.PublicKey, expires int64) (Binding, error) {
	bd, err := NewKey(key, group)
	if err != nil {
		return Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

// KEM binds a KEM key to the identity.
// If group is empty, it will be set to GroupKeys.
func KEM(id quark.Identity, sk quark.PrivateKey, group string, key encaps.PublicKey, expires int64) (Binding, error) {
	bd, err := NewKEM(key, group)
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
func DecodeKey(b Binding) (quark.PublicKey, error) {
	m, err := decodeKey(b, TypeSignKey)
	if err != nil {
		return nil, err
	}
	scheme := sign.ByName(m.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown scheme")
	}
	key, err := scheme.UnpackPublic(m.Key)
	if err != nil {
		return nil, err
	}
	return quark.Pub(key), nil
}

// DecodeKEM decodes a KEM key from the binding.
func DecodeKEM(b Binding) (encaps.PublicKey, error) {
	m, err := decodeKey(b, TypeKEMKey)
	if err != nil {
		return nil, err
	}
	scheme := kem.ByName(m.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown scheme")
	}
	key, err := scheme.UnpackPublic(m.Key)
	if err != nil {
		return nil, err
	}
	return encaps.Pub(key), nil
}
