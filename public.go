package quark

import (
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/sign"
)

var _ Public = (*public)(nil)
var _ pack.CustomEncoder = (*public)(nil)
var _ pack.CustomDecoder = (*public)(nil)

type public struct {
	info KeysetInfo
	sign sign.PublicKey
	kem  kem.PublicKey
}

func (p *public) pub() *public { return p }

// PacketTag implements pack.Packable interface.
func (*public) PacketTag() pack.Tag { return PacketTagPublicKeyset }

// Info returns the info of the keyset.
func (p *public) Info() KeysetInfo { return p.info }

// Identity returns the identity of the keyset.
func (p *public) Identity() Identity { return p.info.Identity }

// ID returns the ID of the keyset.
func (p *public) ID() ID { return p.info.ID }

// Fingerprint returns the fingerprint of the keyset.
func (p *public) Fingerprint() Fingerprint { return p.info.Fingerprint }

// Scheme returns the scheme of the keyset.
func (p *public) Scheme() Scheme { return p.info.Scheme }

// KEM returns the KEM public key.
func (p *public) KEM() kem.PublicKey { return p.kem }

// Sign returns the signature public key.
func (p *public) Sign() sign.PublicKey { return p.sign }

type packablePublic struct {
	KeysetInfo `msgpack:",inline"`
	SignPub    []byte `msgpack:"sign_pub"`
	KEMPub     []byte `msgpack:"kem_pub"`
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *public) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(packablePublic{
		KeysetInfo: p.info,
		SignPub:    p.sign.Bytes(),
		KEMPub:     p.kem.Bytes(),
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *public) DecodeMsgpack(dec *pack.Decoder) error {
	pub := new(packablePublic)
	err := dec.Decode(pub)
	if err != nil {
		return err
	}
	p1, err := NewPublicFromBytes(pub.Identity, pub.Scheme, pub.SignPub, pub.KEMPub)
	if err != nil {
		return err
	}

	*p = *p1.pub()
	return nil
}
