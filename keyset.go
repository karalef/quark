package quark

import (
	"errors"

	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

// Generate generates a new keyset from scheme using crypto/rand.
func Generate(id Identity, scheme Scheme) (*Private, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	signSeed, err := internal.RandRead(nil, scheme.Sign.SeedSize())
	if err != nil {
		return nil, err
	}
	kemSeed, err := internal.RandRead(nil, scheme.KEM.SeedSize())
	if err != nil {
		return nil, err
	}

	return NewPrivate(id, scheme, signSeed, kemSeed)
}

// Identity represents the keyset's identity.
type Identity struct {
	Name  string
	Email string
}

// NewPublic creates a new public keyset.
// It returns ErrInvalidScheme if public keys or hash scheme is nil.
func NewPublic(id Identity, k kem.PublicKey, s sign.PublicKey, h hash.Scheme) (*Public, error) {
	if k == nil || s == nil || h == nil {
		return nil, ErrInvalidScheme
	}
	return &Public{
		identity: id,
		fp:       calculateFingerprint(s, k),
		sign:     s,
		kem:      k,
		hash:     h,
	}, nil
}

// NewPublicFromBytes creates a new public keyset parsing the scheme, signature public key and KEM public key.
func NewPublicFromBytes(id Identity, scheme Scheme, signPub []byte, kemPub []byte) (*Public, error) {
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

	return NewPublic(id, k, s, scheme.Hash)
}

// Public represents a public keyset.
type Public struct {
	identity Identity
	fp       Fingerprint
	sign     sign.PublicKey
	kem      kem.PublicKey
	hash     hash.Scheme
}

// Identity returns the identity of the keyset.
func (p *Public) Identity() Identity { return p.identity }

// ID returns the ID of the keyset.
func (p *Public) ID() KeysetID { return p.fp.ID() }

// Fingerprint returns the fingerprint of the keyset.
func (p *Public) Fingerprint() Fingerprint { return p.fp }

// Scheme returns the scheme of the keyset.
func (p *Public) Scheme() Scheme {
	return Scheme{
		KEM:  p.kem.Scheme(),
		Sign: p.sign.Scheme(),
		Hash: p.hash,
	}
}

// KEM returns the KEM public key.
func (p *Public) KEM() kem.PublicKey { return p.kem }

// Sign returns the signature public key.
func (p *Public) Sign() sign.PublicKey { return p.sign }

// ErrInvalidSeed is returned if the seed size does not match the scheme.
var ErrInvalidSeed = errors.New("invalid seed size")

// NewPrivate creates a new private keyset from scheme and seeds.
func NewPrivate(id Identity, scheme Scheme, signSeed, kemSeed []byte) (*Private, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	if len(signSeed) != scheme.Sign.SeedSize() || len(kemSeed) != scheme.KEM.SeedSize() {
		return nil, ErrInvalidSeed
	}

	// derive keys
	signPriv, signPub := scheme.Sign.DeriveKey(signSeed)
	kemPriv, kemPub := scheme.KEM.DeriveKey(kemSeed)

	pub, err := NewPublic(id, kemPub, signPub, scheme.Hash)
	if err != nil {
		return nil, err
	}

	return &Private{
		pub:      pub,
		signSeed: internal.Copy(signSeed),
		kemSeed:  internal.Copy(kemSeed),
		sign:     signPriv,
		kem:      kemPriv,
	}, nil
}

// Private represents a private keyset.
type Private struct {
	pub      *Public
	signSeed []byte
	kemSeed  []byte
	sign     sign.PrivateKey
	kem      kem.PrivateKey
}

// Public returns the public keyset.
func (p *Private) Public() *Public { return p.pub }

// Identity returns the identity of the keyset.
func (p *Private) Identity() Identity { return p.pub.Identity() }

// ID returns the ID of the keyset.
func (p *Private) ID() KeysetID { return p.pub.ID() }

// Fingerprint returns the fingerprint of the keyset.
func (p *Private) Fingerprint() Fingerprint { return p.pub.Fingerprint() }

// Scheme returns the scheme of the keyset.
func (p *Private) Scheme() Scheme { return p.pub.Scheme() }

// KEM returns the KEM private key.
func (p *Private) KEM() kem.PrivateKey { return p.kem }

// Sign returns the signature private key.
func (p *Private) Sign() sign.PrivateKey { return p.sign }

// Seeds returns the seeds of the keyset.
func (p *Private) Seeds() (signSeed, kemSeed []byte) {
	return internal.Copy(p.signSeed), internal.Copy(p.kemSeed)
}
