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

// KeysetInfo contains the info about the keyset.
type KeysetInfo struct {
	ID          ID          `msgpack:"-"`
	Fingerprint Fingerprint `msgpack:"-"`

	Identity Identity `msgpack:"identity"`
	Scheme   Scheme   `msgpack:"scheme"`
}

// Keyset represents a keyset.
type Keyset interface {
	pack.Packable

	// Info returns the info of the keyset.
	Info() KeysetInfo

	// Identity returns the identity of the keyset.
	Identity() Identity

	// ID returns the ID of the keyset.
	ID() ID

	// Fingerprint returns the fingerprint of the keyset.
	Fingerprint() Fingerprint

	// Scheme returns the scheme of the keyset.
	Scheme() Scheme

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

	// ChangeIdentity changes the identity of the keyset.
	ChangeIdentity(Identity) error

	// KEM returns the KEM public key.
	KEM() kem.PrivateKey

	// Sign returns the signature public key.
	Sign() sign.PrivateKey

	priv() *private
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
	fp := calculateFingerprint(s, k)
	return &public{
		info: KeysetInfo{
			ID:          fp.ID(),
			Fingerprint: fp,
			Identity:    id,
			Scheme:      Scheme{Sign: s.Scheme(), KEM: k.Scheme()},
		},
		sign: s,
		kem:  k,
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
