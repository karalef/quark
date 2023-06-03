package quark

import (
	"github.com/karalef/quark/internal"
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
	return p.public.changeIdentity(id, p)
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
	p1, err := newPrivate(priv.Identity, priv.Scheme, priv.SignSeed, priv.KEMSeed)
	if err != nil {
		return err
	}

	*p = *p1
	return nil
}

func newPrivate(id Identity, scheme Scheme, signSeed, kemSeed []byte) (*private, error) {
	signPriv, signPub, err := scheme.Sign.DeriveKey(signSeed)
	if err != nil {
		return nil, err
	}
	kemPriv, kemPub, err := scheme.KEM.DeriveKey(kemSeed)
	if err != nil {
		return nil, err
	}

	pub, err := newPublic(id, scheme, signPub, kemPub, signPriv)
	if err != nil {
		return nil, err
	}

	return &private{
		public:   pub,
		signSeed: internal.Copy(signSeed),
		kemSeed:  internal.Copy(kemSeed),
		sign:     signPriv,
		kem:      kemPriv,
	}, nil
}
