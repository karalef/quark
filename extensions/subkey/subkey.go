package subkey

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/internal"
)

// subkey bind types
const (
	TypeGroupQuarkKey quark.BindType = quark.BindTypeGroupQuark + ".key"
	TypeSignKey       quark.BindType = TypeGroupQuarkKey + ".sign"
	TypeKEMKey        quark.BindType = TypeGroupQuarkKey + ".kem"
)

// New returns a new subkey binding data.
func New[Scheme crypto.Scheme](subkey crypto.Key[Scheme], md quark.Metadata) (quark.BindingData, error) {
	t := TypeSignKey
	if _, ok := subkey.(kem.PublicKey); ok {
		t = TypeKEMKey
	}
	return quark.NewBindingData(quark.KeyModel{
		Algorithm: subkey.Scheme().Name(),
		Key:       subkey.Pack(),
	}, t, md)
}

// Bind binds a subkey to the identity.
func Bind[Scheme crypto.Scheme](id *quark.Identity, sk sign.PrivateKey, md quark.Metadata, subkey crypto.Key[Scheme], expires int64) (quark.Binding, error) {
	bd, err := New(subkey, md)
	if err != nil {
		return quark.Binding{}, err
	}
	return id.Bind(sk, bd, expires)
}

// Decode decodes a key model from the subkey binding.
func Decode(b quark.Binding) (*quark.KeyModel, error) {
	return quark.DecodeBinding[quark.KeyModel](b)
}

// ErrWrongType is returned when an wrong binding type is provided.
var ErrWrongType = errors.New("wrong binding type")

// DecodeSign decodes a signing subkey from the binding.
func DecodeSign(b quark.Binding) (sign.PublicKey, error) {
	if b.Type != TypeSignKey {
		return nil, ErrWrongType
	}
	m, err := Decode(b)
	if err != nil {
		return nil, err
	}
	scheme := sign.ByName(m.Algorithm)
	if scheme == nil {
		return nil, internal.ErrUnknownScheme
	}
	return scheme.UnpackPublic(m.Key)
}

// DecodeKEM decodes a KEM subkey from the binding.
func DecodeKEM(b quark.Binding) (kem.PublicKey, error) {
	if b.Type != TypeKEMKey {
		return nil, ErrWrongType
	}
	m, err := Decode(b)
	if err != nil {
		return nil, err
	}
	scheme := kem.ByName(m.Algorithm)
	if scheme == nil {
		return nil, errors.New("unknown scheme")
	}
	return scheme.UnpackPublic(m.Key)
}
