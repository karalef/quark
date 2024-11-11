package subkey

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// subkey bind types
const (
	TypeBindKey = "bind.key"
	TypeSignKey = TypeBindKey + ".sign"
	TypeKEMKey  = TypeBindKey + ".kem"
)

// NewSign returns a new sign subkey.
func NewSign(k sign.PublicKey) Subkey {
	return Subkey{
		typ: TypeSignKey,
		key: k,
	}
}

// NewKEM returns a new kem subkey.
func NewKEM(k kem.PublicKey) Subkey {
	return Subkey{
		typ: TypeKEMKey,
		key: k,
	}
}

// Subkey is a subkey.
type Subkey struct {
	key crypto.Key
	typ string
}

func (s Subkey) Key() crypto.Key { return s.key }

type model struct {
	Type           string `msgpack:"type"`
	quark.KeyModel `msgpack:",inline"`
}

func (s Subkey) CertType() string { return s.typ }

func (s Subkey) Copy() Subkey {
	cp := s.key.Pack()
	var err error
	if s.typ == TypeKEMKey {
		s.key, err = s.key.Scheme().(kem.Scheme).UnpackPublic(cp)
	} else {
		s.key, err = s.key.Scheme().(sign.Scheme).UnpackPublic(cp)
	}
	if err != nil {
		panic(err)
	}
	return s
}

func (s Subkey) BindTo(k *quark.Key, sk sign.PrivateKey, expires int64) (quark.CertID, error) {
	if s.key == nil {
		return quark.CertID{}, nil
	}
	return quark.Bind(k, sk, expires, s)
}

func (s Subkey) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(model{
		Type:     s.typ,
		KeyModel: quark.NewKeyModel(s.key),
	})
}

func (s *Subkey) DecodeMsgpack(dec *pack.Decoder) error {
	m := new(model)
	err := dec.Decode(m)
	if err != nil {
		return err
	}
	var key crypto.Key
	switch m.Type {
	case TypeSignKey:
		key, err = sign.UnpackPublic(m.Algorithm, m.Key)
	case TypeKEMKey:
		key, err = kem.UnpackPublic(m.Algorithm, m.Key)
	default:
		return errors.New("unknown subkey type")
	}
	if err != nil {
		return err
	}
	*s = Subkey{
		typ: m.Type,
		key: key,
	}
	return nil
}

// Bind binds the sign subkey to the key.
func Bind(k *quark.Key, sk sign.PrivateKey, expires int64, key crypto.Key) (quark.CertID, error) {
	typ := TypeSignKey
	if _, ok := key.(kem.PublicKey); ok {
		typ = TypeKEMKey
	}
	return Subkey{
		typ: typ,
		key: key,
	}.BindTo(k, sk, expires)
}

// FromRaw extracts the public key from a raw certificate.
func FromRaw(b quark.RawCertificate) (Subkey, error) {
	c, err := quark.CertificateAs[Subkey](b)
	if err != nil {
		return Subkey{}, err
	}
	return c.Data, nil
}
