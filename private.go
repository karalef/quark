package quark

import (
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/sign"
)

var _ Private = (*private)(nil)
var _ pack.CustomEncoder = (*private)(nil)
var _ pack.CustomDecoder = (*private)(nil)

type private struct {
	*public
	signSeed []byte
	kemSeed  []byte
	sign     sign.PrivateKey
	kem      kem.PrivateKey
}

func (p *private) priv() *private { return p }

// PacketTag implements pack.Packable interface.
func (*private) PacketTag() pack.Tag { return PacketTagPrivateKeyset }

// Public returns the public keyset.
func (p *private) Public() Public { return p.public }

// ChangeIdentity changes the identity of the keyset.
func (p *private) ChangeIdentity(id Identity) error {
	if !id.IsValid() {
		return ErrInvalidIdentity
	}
	p.info.Identity = id
	return nil
}

// KEM returns the KEM private key.
func (p *private) KEM() kem.PrivateKey { return p.kem }

// Sign returns the signature private key.
func (p *private) Sign() sign.PrivateKey { return p.sign }

type packablePrivate struct {
	KeysetInfo `msgpack:",inline"`
	SignSeed   []byte `msgpack:"sign_seed"`
	KEMSeed    []byte `msgpack:"kem_seed"`
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *private) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(packablePrivate{
		KeysetInfo: p.public.info,
		SignSeed:   p.signSeed,
		KEMSeed:    p.kemSeed,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *private) DecodeMsgpack(dec *pack.Decoder) error {
	priv := new(packablePrivate)
	err := dec.Decode(priv)
	if err != nil {
		return err
	}
	p1, err := NewPrivate(priv.Identity, priv.Scheme, priv.SignSeed, priv.KEMSeed)
	if err != nil {
		return err
	}

	*p = *p1.priv()
	return nil
}
