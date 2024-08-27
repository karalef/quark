package bind

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
)

// well-known bind types
const (
	TypeGroupQuarkKey Type = quark.BindTypeGroupQuark + ".key"
	TypeSignKey       Type = TypeGroupQuarkKey + ".sign"
	TypeKEMKey        Type = TypeGroupQuarkKey + ".kem"
)

// NewKey returns a new key binding data.
func NewKey[Scheme crypto.Scheme](key crypto.Key[Scheme], md Metadata) (BindingData, error) {
	if key == nil {
		return BindingData{}, errors.New("nil key")
	}
	t := TypeSignKey
	if _, ok := key.(kem.PublicKey); ok {
		t = TypeKEMKey
	}
	return NewPackable(quark.KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}, t, md)
}

// Key binds a key to the identity.
func Key[Scheme crypto.Scheme](id *quark.Identity, sk sign.PrivateKey, md Metadata, key crypto.Key[Scheme], expires int64) (Binding, error) {
	bd, err := NewKey(key, md)
	if err != nil {
		return Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

func decodeKey(b Binding, typ Type) (*quark.KeyModel, error) {
	if b.Type != typ {
		return nil, errors.New("invalid type")
	}
	return DecodePackable[quark.KeyModel](b)
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
