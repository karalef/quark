package subkey

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// subkey bind types
const (
	TypeGroupQuarkKey quark.BindType = quark.BindTypeGroupQuark + ".key"
	TypeSignKey       quark.BindType = TypeGroupQuarkKey + ".sign"
	TypeKEMKey        quark.BindType = TypeGroupQuarkKey + ".kem"
)

var _ quark.Bindable[SignSubkey] = SignSubkey{}
var _ quark.Bindable[KEMSubkey] = KEMSubkey{}

type SignSubkey struct {
	sign.PublicKey
}

type KEMSubkey struct {
	kem.PublicKey
}

func (SignSubkey) BindType() quark.BindType { return TypeSignKey }
func (KEMSubkey) BindType() quark.BindType  { return TypeKEMKey }
func (s SignSubkey) Copy() SignSubkey {
	b := s.PublicKey.Pack()
	cpy, err := s.Scheme().(sign.Scheme).UnpackPublic(b)
	if err != nil {
		panic(err)
	}
	return SignSubkey{cpy}
}
func (k KEMSubkey) Copy() KEMSubkey {
	b := k.PublicKey.Pack()
	cpy, err := k.Scheme().(kem.Scheme).UnpackPublic(b)
	if err != nil {
		panic(err)
	}
	return KEMSubkey{cpy}
}

func (s SignSubkey) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(quark.KeyModel{
		Algorithm: s.Scheme().Name(),
		Key:       s.Pack(),
	})
}
func (k KEMSubkey) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(quark.KeyModel{
		Algorithm: k.Scheme().Name(),
		Key:       k.Pack(),
	})
}

func (s *SignSubkey) DecodeMsgpack(dec *pack.Decoder) error {
	m := new(quark.KeyModel)
	err := dec.Decode(m)
	if err != nil {
		return err
	}
	key, err := sign.UnpackPublic(m.Algorithm, m.Key)
	if err != nil {
		return err
	}
	s.PublicKey = key
	return nil
}
func (k *KEMSubkey) DecodeMsgpack(dec *pack.Decoder) error {
	m := new(quark.KeyModel)
	err := dec.Decode(m)
	if err != nil {
		return err
	}
	key, err := kem.UnpackPublic(m.Algorithm, m.Key)
	if err != nil {
		return err
	}
	k.PublicKey = key
	return nil
}

// BindSign binds a subkey to an identity.
func BindSign(id *quark.Key, sk sign.PrivateKey, subkey sign.PublicKey, expires int64) (quark.Binding[SignSubkey], error) {
	if subkey == nil {
		return quark.Binding[SignSubkey]{}, nil
	}
	return quark.Bind(id, sk, expires, SignSubkey{subkey})
}

// BindKEM binds a subkey to an identity.
func BindKEM(id *quark.Key, sk sign.PrivateKey, subkey kem.PublicKey, expires int64) (quark.Binding[KEMSubkey], error) {
	if subkey == nil {
		return quark.Binding[KEMSubkey]{}, nil
	}
	return quark.Bind(id, sk, expires, KEMSubkey{subkey})
}

// SignFrom extracts the public key from a binding.
func SignFrom(b quark.RawBinding) (sign.PublicKey, error) {
	k, err := quark.BindingAs[SignSubkey](b)
	if err != nil {
		return nil, err
	}
	return k.GetData().PublicKey, nil
}

// KEMFrom extracts the public key from a binding.
func KEMFrom(b quark.RawBinding) (kem.PublicKey, error) {
	k, err := quark.BindingAs[KEMSubkey](b)
	if err != nil {
		return nil, err
	}
	return k.GetData().PublicKey, nil
}
