package quark

import (
	"errors"

	"github.com/karalef/quark/hash"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

func Generate(id Identity, scheme Scheme) (PrivateKeyset, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	signPriv, signPub, err := sign.Generate(scheme.Sign, nil)
	if err != nil {
		return nil, err
	}

	kemPriv, kemPub, err := kem.Generate(scheme.KEM, nil)
	if err != nil {
		return nil, err
	}

	return &private{
		public: &public{
			identity: id,
			sign:     signPub,
			kem:      kemPub,
			hash:     scheme.Hash,
		},
		sign: signPriv,
		kem:  kemPriv,
	}, nil
}

func SchemeOf(k PublicKeyset) Scheme {
	return Scheme{
		KEM:  k.KEMPublicKey().Scheme(),
		Sign: k.SignPublicKey().Scheme(),
		Hash: k.Hash(),
	}
}

type PublicKeyset interface {
	Identity() Identity

	KEMPublicKey() kem.PublicKey
	SignPublicKey() sign.PublicKey

	Hash() hash.Scheme
}

type PrivateKeyset interface {
	PublicKeyset

	KEMPrivateKey() kem.PrivateKey
	SignPrivateKey() sign.PrivateKey
}

type Identity struct {
	Name  string
	Email string
}

func NewPrivateKeyset(pk PublicKeyset, k kem.PrivateKey, s sign.PrivateKey) (*private, error) {
	pub, ok := pk.(*public)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	return &private{
		public: pub,
		sign:   s,
		kem:    k,
	}, nil
}

var _ PrivateKeyset = &private{}

type private struct {
	*public
	sign sign.PrivateKey
	kem  kem.PrivateKey
}

func (p *private) KEMPrivateKey() kem.PrivateKey   { return p.kem }
func (p *private) SignPrivateKey() sign.PrivateKey { return p.sign }

func NewPublicKeyset(id Identity, k kem.PublicKey, s sign.PublicKey, h hash.Scheme) (*public, error) {
	return &public{
		identity: id,
		sign:     s,
		kem:      k,
		hash:     h,
	}, nil
}

var _ PublicKeyset = &public{}

type public struct {
	identity Identity
	sign     sign.PublicKey
	kem      kem.PublicKey
	hash     hash.Scheme
}

func (p *public) Identity() Identity            { return p.identity }
func (p *public) KEMPublicKey() kem.PublicKey   { return p.kem }
func (p *public) SignPublicKey() sign.PublicKey { return p.sign }
func (p *public) Hash() hash.Scheme             { return p.hash }
