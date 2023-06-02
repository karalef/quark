package quark

import (
	"errors"
	"time"

	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/sign"
)

// ErrPublicKeysetSignature is returned if the public keyset signature is invalid.
type ErrPublicKeysetSignature struct {
	err          error
	verification bool
}

func (e ErrPublicKeysetSignature) Error() string {
	if e.verification {
		return "public keyset signature cannot be verified: " + e.err.Error()
	}
	return "public keyset signature: " + e.err.Error()
}

var _ Public = (*public)(nil)
var _ pack.CustomEncoder = (*public)(nil)
var _ pack.CustomDecoder = (*public)(nil)

type public struct {
	info    KeysetInfo
	signKey sign.PublicKey
	kemKey  kem.PublicKey

	signature Signature
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
func (p *public) KEM() kem.PublicKey { return p.kemKey }

// Sign returns the signature public key.
func (p *public) Sign() sign.PublicKey { return p.signKey }

func (p *public) sign(issuer Private) error {
	pubPart, err := pack.MarshalBinary(newPublicPart(p))
	if err != nil {
		return err
	}
	sig, err := Sign(pubPart, issuer)
	if err != nil {
		return err
	}
	p.signature = *sig
	return nil
}

func (p *public) changeIdentity(identity Identity, issuer Private) error {
	if !identity.IsValid() {
		return ErrInvalidIdentity
	}
	p1 := *p
	p1.info.Identity = identity
	if err := p1.sign(issuer); err != nil {
		return err
	}
	*p = p1
	return nil
}

func newPublicPart(pub *public) publicPart {
	return publicPart{
		Identity: pub.Identity(),
		SignPub:  pub.signKey.Bytes(),
		KEMPub:   pub.kemKey.Bytes(),
	}
}

// publicPart is used to create a public keyset signature.
type publicPart struct {
	Identity Identity `msgpack:"identity"`
	SignPub  []byte   `msgpack:"sign_pub"`
	KEMPub   []byte   `msgpack:"kem_pub"`
}

type packablePublic[T publicPart | pack.RawMessage[publicPart]] struct {
	Scheme    Scheme    `msgpack:"scheme"`
	Public    T         `msgpack:",inline"`
	Signature Signature `msgpack:"signature"`
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *public) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(packablePublic[publicPart]{
		Scheme:    p.info.Scheme,
		Public:    newPublicPart(p),
		Signature: p.signature,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *public) DecodeMsgpack(dec *pack.Decoder) error {
	pubRaw := new(packablePublic[pack.RawMessage[publicPart]])
	if err := dec.Decode(pubRaw); err != nil {
		return err
	}

	sig := pubRaw.Signature
	if !sig.IsValid() {
		return ErrPublicKeysetSignature{
			err:          &sig,
			verification: true,
		}
	}

	pubPart, err := pubRaw.Public.Unpack()
	if err != nil {
		return err
	}

	if !pubPart.Identity.IsValid() {
		return ErrInvalidIdentity
	}

	scheme := pubRaw.Scheme
	signKey, err := scheme.Sign.UnpackPublic(pubPart.SignPub)
	if err != nil {
		return err
	}
	kemKey, err := scheme.KEM.UnpackPublic(pubPart.KEMPub)
	if err != nil {
		return err
	}

	fp := calculateFingerprint(pubPart.SignPub, pubPart.KEMPub)
	pub := &public{
		info: KeysetInfo{
			ID:          fp.ID(),
			Fingerprint: fp,
			Identity:    pubPart.Identity,
			Scheme:      scheme,
		},
		signKey:   signKey,
		kemKey:    kemKey,
		signature: sig,
	}

	ok, err := Verify(pubRaw.Public.RawMessage, sig, pub)
	if err != nil || !ok {
		if err == nil {
			err = errors.New("wrong signature")
		}
		return ErrPublicKeysetSignature{
			err:          err,
			verification: true,
		}
	}

	*p = *pub

	return nil
}

// newPublic is used to create a public keyset from the newly generated keys.
func newPublic(identity Identity, signPub sign.PublicKey, kemPub kem.PublicKey, signer sign.PrivateKey) (*public, error) {
	if signer == nil {
		panic("nil signer")
	}
	if !identity.IsValid() {
		return nil, ErrInvalidIdentity
	}
	if signPub == nil || kemPub == nil {
		return nil, ErrInvalidScheme
	}

	scheme := Scheme{
		Sign: signPub.Scheme(),
		KEM:  kemPub.Scheme(),
	}
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	pubPart := publicPart{
		Identity: identity,
		SignPub:  signPub.Bytes(),
		KEMPub:   kemPub.Bytes(),
	}

	p, err := pack.MarshalBinary(pubPart)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(p)
	if err != nil {
		return nil, err
	}

	fp := calculateFingerprint(pubPart.SignPub, pubPart.KEMPub)
	id := fp.ID()
	return &public{
		info: KeysetInfo{
			ID:          id,
			Fingerprint: fp,
			Identity:    identity,
			Scheme:      scheme,
		},
		signKey: signPub,
		kemKey:  kemPub,
		signature: Signature{
			ID:        id,
			Signature: sig,
			Time:      time.Now().Unix(),
		},
	}, nil
}
