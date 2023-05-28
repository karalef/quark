package quark

import (
	"errors"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/sign"
)

// Generate generates a new keyset from scheme using crypto/rand.
func Generate(id Identity, scheme Scheme) (Private, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	signSeed := internal.Rand(scheme.Sign.SeedSize())
	kemSeed := internal.Rand(scheme.KEM.SeedSize())

	return NewPrivate(id, scheme, signSeed, kemSeed)
}

// Identity represents the keyset's identity.
type Identity struct {
	Name    string `msgpack:"name"`
	Email   string `msgpack:"email,omitempty"`
	Comment string `msgpack:"comment,omitempty"`
}

// IsValid returns true if the identity is valid.
func (i Identity) IsValid() bool {
	return i.Name != ""
}

// ErrInvalidIdentity is returned if the identity is invalid.
var ErrInvalidIdentity = errors.New("invalid identity")

// Keyset represents a keyset.
type Keyset interface {
	pack.Packable

	// Identity returns the identity of the keyset.
	Identity() Identity

	// ID returns the ID of the keyset.
	ID() ID

	// Fingerprint returns the fingerprint of the keyset.
	Fingerprint() Fingerprint

	// Scheme returns the scheme of the keyset.
	Scheme() Scheme

	// ChangeIdentity changes the identity of the keyset.
	ChangeIdentity(Identity) error

	pub() *public
}

// Public represents a public keyset.
type Public interface {
	Keyset

	// KEM returns the KEM public key.
	KEM() kem.PublicKey

	// Sign returns the signature public key.
	Sign() sign.PublicKey
}

// Private represents a private keyset.
type Private interface {
	Keyset

	// Public returns the public keyset.
	Public() Public

	// KEM returns the KEM public key.
	KEM() kem.PrivateKey

	// Sign returns the signature public key.
	Sign() sign.PrivateKey
}

// NewPublic creates a new public keyset.
// It returns ErrInvalidScheme if public keys or hash scheme is nil.
func NewPublic(id Identity, s sign.PublicKey, k kem.PublicKey) (Public, error) {
	if k == nil || s == nil {
		return nil, ErrInvalidScheme
	}
	if !id.IsValid() {
		return nil, ErrInvalidIdentity
	}
	return &public{
		identity: id,
		fp:       calculateFingerprint(s, k),
		sign:     s,
		kem:      k,
	}, nil
}

// NewPublicFromBytes creates a new public keyset parsing the scheme, signature public key and KEM public key.
func NewPublicFromBytes(id Identity, scheme Scheme, signPub []byte, kemPub []byte) (Public, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	s, err := scheme.Sign.UnpackPublic(signPub)
	if err != nil {
		return nil, err
	}
	k, err := scheme.KEM.UnpackPublic(kemPub)
	if err != nil {
		return nil, err
	}

	return NewPublic(id, s, k)
}

var _ Public = (*public)(nil)
var _ pack.CustomEncoder = (*public)(nil)
var _ pack.CustomDecoder = (*public)(nil)

type public struct {
	identity Identity
	fp       Fingerprint
	sign     sign.PublicKey
	kem      kem.PublicKey
}

func (p *public) pub() *public { return p }

// PacketTag implements pack.Packable interface.
func (*public) PacketTag() pack.Tag { return PacketTagPublicKeyset }

// Identity returns the identity of the keyset.
func (p *public) Identity() Identity { return p.identity }

// ID returns the ID of the keyset.
func (p *public) ID() ID { return p.fp.ID() }

// Fingerprint returns the fingerprint of the keyset.
func (p *public) Fingerprint() Fingerprint { return p.fp }

// Scheme returns the scheme of the keyset.
func (p *public) Scheme() Scheme {
	return Scheme{
		KEM:  p.kem.Scheme(),
		Sign: p.sign.Scheme(),
	}
}

// ChangeIdentity changes the identity of the keyset.
func (p *public) ChangeIdentity(id Identity) error {
	if !id.IsValid() {
		return ErrInvalidIdentity
	}
	p.identity = id
	return nil
}

// KEM returns the KEM public key.
func (p *public) KEM() kem.PublicKey { return p.kem }

// Sign returns the signature public key.
func (p *public) Sign() sign.PublicKey { return p.sign }

// ErrInvalidSeed is returned if the seed size does not match the scheme.
var ErrInvalidSeed = errors.New("invalid seed size")

// NewPrivate creates a new private keyset from scheme and seeds.
func NewPrivate(id Identity, scheme Scheme, signSeed, kemSeed []byte) (Private, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	// derive keys
	signPriv, signPub, err := scheme.Sign.DeriveKey(signSeed)
	if err != nil {
		return nil, err
	}
	kemPriv, kemPub, err := scheme.KEM.DeriveKey(kemSeed)
	if err != nil {
		return nil, err
	}

	pub, err := NewPublic(id, signPub, kemPub)
	if err != nil {
		return nil, err
	}

	return &private{
		public:   pub.(*public),
		signSeed: internal.Copy(signSeed),
		kemSeed:  internal.Copy(kemSeed),
		sign:     signPriv,
		kem:      kemPriv,
	}, nil
}

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

// PacketTag implements pack.Packable interface.
func (*private) PacketTag() pack.Tag { return PacketTagPrivateKeyset }

// Public returns the public keyset.
func (p *private) Public() Public { return p.public }

// KEM returns the KEM private key.
func (p *private) KEM() kem.PrivateKey { return p.kem }

// Sign returns the signature private key.
func (p *private) Sign() sign.PrivateKey { return p.sign }

type keysetData struct {
	Identity `msgpack:",inline"`
	Scheme   Scheme `msgpack:"scheme"`
}

func packKeysetData(p *public) keysetData {
	return keysetData{
		Identity: p.Identity(),
		Scheme:   p.Scheme(),
	}
}

type packablePublic struct {
	keysetData `msgpack:",inline"`
	SignPub    []byte `msgpack:"sign_pub"`
	KEMPub     []byte `msgpack:"kem_pub"`
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *public) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(packablePublic{
		keysetData: packKeysetData(p),
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

type packablePrivate struct {
	keysetData `msgpack:",inline"`
	SignSeed   []byte `msgpack:"sign_seed"`
	KEMSeed    []byte `msgpack:"kem_seed"`
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *private) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(packablePrivate{
		keysetData: packKeysetData(p.public),
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

	*p = *p1.(*private)
	return nil
}
