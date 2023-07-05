package quark

import (
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

var _ Private = (*private)(nil)
var _ pack.CustomEncoder = (*private)(nil)
var _ pack.CustomDecoder = (*private)(nil)

type private struct {
	*public

	privateKeyset
}

func (p *private) priv() *private { return p }

// PacketTag implements pack.Packable interface.
func (*private) PacketTag() pack.Tag { return PacketTagPrivateKeyset }

// Public returns the public keyset.
func (p *private) Public() Public { return p.public }

// ChangeIdentity changes the identity of the keyset.
func (p *private) ChangeIdentity(id Identity) error {
	err := p.public.changeIdentity(id)
	if err != nil {
		return err
	}
	return p.public.sign(p)
}

// ChangeExpiry changes the expiry of the keyset.
func (p *private) ChangeExpiry(expiry int64) error {
	err := p.public.changeExpiry(expiry)
	if err != nil {
		return err
	}
	return p.public.sign(p)
}

// Revoke revokes the keyset.
func (p *private) Revoke(reason string) error {
	err := p.public.revoke(reason)
	if err != nil {
		return err
	}
	return p.public.sign(p)
}

// Cert returns the certification private key.
func (p *private) Cert() sign.PrivateKey { return p.privateKeyset.cert }

// Sign returns the signature private key.
func (p *private) Sign() sign.PrivateKey { return p.privateKeyset.sign }

// KEM returns the KEM private key.
func (p *private) KEM() kem.PrivateKey { return p.privateKeyset.kem }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *private) EncodeMsgpack(enc *pack.Encoder) error {
	err := enc.Encode(p.public.keysetInfo)
	if err != nil {
		return err
	}
	err = enc.Encode(p.privateKeyset)
	if err != nil {
		return err
	}
	return enc.Encode(p.public.keysetSigs)
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *private) DecodeMsgpack(dec *pack.Decoder) error {
	p.public = new(public)

	err := dec.Decode(&p.public.keysetInfo)
	if err != nil {
		return err
	}
	err = dec.Decode(&p.privateKeyset)
	if err != nil {
		return err
	}
	p.public.publicKeyset = p.privateKeyset.public

	return dec.Decode(&p.public.keysetSigs)
}

func newPrivate(id Identity, scheme Scheme, expires int64, certSeed, signSeed, kemSeed []byte) (*private, error) {
	ks, err := newPrivateKeyset(scheme, certSeed, signSeed, kemSeed)
	if err != nil {
		return nil, err
	}

	pub, err := newPublic(id, expires, ks.public)
	if err != nil {
		return nil, err
	}

	priv := &private{
		public:        pub,
		privateKeyset: ks,
	}

	err = pub.sign(priv)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
