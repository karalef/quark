package subkey

import (
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

func NewSign(k sign.PublicKey, usage Usage) (Subkey, error) {
	if usage.Has(UsageEncrypt) {
		return Subkey{}, ErrInvalidUsage
	}
	return Subkey{
		typ:   TypeSignKey,
		key:   k,
		usage: usage,
	}, nil
}

func NewKEM(k kem.PublicKey, usage Usage) (Subkey, error) {
	if usage.Has(UsageSign | UsageCertify) {
		return Subkey{}, ErrInvalidUsage
	}
	return Subkey{
		typ:   TypeKEMKey,
		key:   k,
		usage: usage,
	}, nil
}

// Subkey is a subkey.
type Subkey struct {
	key   crypto.Key
	typ   string
	usage Usage
}

func (s Subkey) Key() crypto.Key { return s.key }
func (s Subkey) Usage() Usage    { return s.usage }

type model struct {
	typ            string `msgpack:"type"`
	quark.KeyModel `msgpack:",inline"`
	usage          Usage `msgpack:"usage"`
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

func (s Subkey) BindTo(id *quark.Key, sk sign.PrivateKey, expires int64) (quark.Certificate[Subkey], error) {
	if s.Key == nil {
		return quark.Certificate[Subkey]{}, nil
	}
	return quark.Bind(id, sk, expires, s)
}

func (s Subkey) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(model{
		typ:      s.typ,
		usage:    s.usage,
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
	if m.typ == TypeKEMKey {
		key, err = kem.UnpackPublic(m.Algorithm, m.Key)
	} else {
		key, err = sign.UnpackPublic(m.Algorithm, m.Key)
	}
	if err != nil {
		return err
	}
	*s = Subkey{
		typ:   m.typ,
		key:   key,
		usage: m.usage,
	}
	return nil
}

// BindSign binds the sign subkey to the key.
func BindSign(id *quark.Key, sk sign.PrivateKey, expires int64,
	key sign.PublicKey, usage Usage,
) (quark.Certificate[Subkey], error) {
	s, err := NewSign(key, usage)
	if err != nil {
		return quark.Certificate[Subkey]{}, err
	}
	return s.BindTo(id, sk, expires)
}

// BindKEM binds the kem subkey to the key.
func BindKEM(id *quark.Key, sk sign.PrivateKey, expires int64,
	key kem.PublicKey, usage Usage,
) (quark.Certificate[Subkey], error) {
	s, err := NewKEM(key, usage)
	if err != nil {
		return quark.Certificate[Subkey]{}, err
	}
	return s.BindTo(id, sk, expires)
}

// FromRaw extracts the public key from a raw certificate.
func FromRaw(b quark.RawCertificate) (Subkey, error) {
	c, err := quark.CertificateAs[Subkey](b)
	if err != nil {
		return Subkey{}, err
	}
	return c.Data, nil
}
