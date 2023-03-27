package quark

import (
	cryptorand "crypto/rand"
	"io"

	"github.com/karalef/quark/cipher"
	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

func Generate(rand io.Reader, id Identity, scheme Scheme) (PrivateKeyset, error) {
	if !scheme.IsValid() {
		return nil, ErrInvalidScheme
	}

	if rand == nil {
		rand = cryptorand.Reader
	}

	signPriv, signPub, err := scheme.Sign.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	kemPriv, kemPub, err := scheme.KEM.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return &private{
		public: &public{
			identity: id,
			sign:     signPub,
			kem:      kemPub,
			cipher:   scheme.Cipher,
			hash:     scheme.Hash,
		},
		sign: signPriv,
		kem:  kemPriv,
	}, nil
}

func SchemeOf(k PublicKeyset) Scheme {
	return Scheme{
		KEM:    k.KEMPublicKey().Scheme(),
		Cipher: k.CipherScheme(),
		Sign:   k.SignPublicKey().Scheme(),
		Hash:   k.Hash(),
	}
}

type PublicKeyset interface {
	Identity() Identity

	KEMPublicKey() kem.PublicKey
	SignPublicKey() sign.PublicKey

	CipherScheme() cipher.Scheme
	Hash() HashScheme

	// Encapsulate generates and encapsulates the key and creates a new Cipher with generated key.
	Encapsulate() ([]byte, cipher.Cipher, error)

	// Verify calculates the message hash and verifies the signature.
	Verify(msg []byte, signature []byte) (bool, error)
}

type PrivateKeyset interface {
	PublicKeyset

	KEMPrivateKey() kem.PrivateKey
	SignPrivateKey() sign.PrivateKey

	// Decapsulate decapsulates the ciphertext and creates a new Cipher with decapsulated key.
	Decapsulate(ciphertext []byte) (cipher.Cipher, error)

	// Sign hashes and signs the message.
	Sign(msg []byte) ([]byte, error)
}

type Identity struct {
	Name  string
	Email string
}

func validateKEMSet(k kem.Scheme, c cipher.Scheme) bool {
	return k.SharedKeySize() == c.KeySize()
}

func NewPrivateKeyset(id Identity, k kem.PrivateKey, ciph cipher.Scheme, s sign.PrivateKey, h HashScheme) (*private, error) {
	pub, err := NewPublicKeyset(id, k.Public(), ciph, s.Public(), h)
	if err != nil {
		return nil, err
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

func (p *private) Decapsulate(ciphertext []byte) (cipher.Cipher, error) {
	key, err := p.kem.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	return p.cipher.Unpack(key)
}

func (p *private) Sign(msg []byte) ([]byte, error) {
	return p.sign.Sign(p.hash.Sum(msg))
}

func NewPublicKeyset(id Identity, k kem.PublicKey, ciph cipher.Scheme, s sign.PublicKey, h HashScheme) (*public, error) {
	if !validateKEMSet(k.Scheme(), ciph) {
		return nil, ErrInvalidScheme
	}
	return &public{
		identity: id,
		sign:     s,
		kem:      k,
		cipher:   ciph,
		hash:     h,
	}, nil
}

var _ PublicKeyset = &public{}

type public struct {
	identity Identity
	sign     sign.PublicKey
	kem      kem.PublicKey
	cipher   cipher.Scheme
	hash     HashScheme
}

func (p *public) Identity() Identity            { return p.identity }
func (p *public) KEMPublicKey() kem.PublicKey   { return p.kem }
func (p *public) SignPublicKey() sign.PublicKey { return p.sign }
func (p *public) CipherScheme() cipher.Scheme   { return p.cipher }
func (p *public) Hash() HashScheme              { return p.hash }

func (p *public) Encapsulate() ([]byte, cipher.Cipher, error) {
	ct, ss, err := p.kem.Encapsulate()
	if err != nil {
		return nil, nil, err
	}
	ciph, err := p.cipher.Unpack(ss)
	if err != nil {
		return nil, nil, err
	}
	return ct, ciph, nil
}

func (p *public) Verify(msg []byte, signature []byte) (bool, error) {
	return p.sign.Verify(p.hash.Sum(msg), signature)
}
