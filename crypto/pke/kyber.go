package pke

import (
	"crypto/subtle"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/pke/kyber"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(Kyber512)
	Register(Kyber768)
	Register(Kyber1024)
}

// kem schemes.
var (
	Kyber512  = kyberScheme{"Kyber512", kyber.Kyber512}
	Kyber768  = kyberScheme{"Kyber768", kyber.Kyber768}
	Kyber1024 = kyberScheme{"Kyber1024", kyber.Kyber1024}
)

var _ Scheme = kyberScheme{}

type kyberScheme struct {
	scheme.String
	kyber.Scheme
}

func (s kyberScheme) PrivateKeySize() int { return s.Scheme.PrivateKeySize() + s.PublicKeySize() }

func (s kyberScheme) DeriveKey(seed []byte) (PrivateKey, PublicKey, error) {
	if len(seed) != s.SeedSize() {
		return nil, nil, ErrSeedSize
	}
	pub, priv := s.Scheme.DeriveKey(seed)
	pk, sk := newKeys(&kyberPubKey{pub, s}, &kyberPrivKey{priv, pub, s})
	return sk, pk, nil
}

func (s kyberScheme) UnpackPublic(key []byte) (PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, ErrKeySize
	}
	pub := s.Scheme.UnpackPublic(key)
	return newPub(&kyberPubKey{sch: s, pk: pub}), nil
}

func (s kyberScheme) UnpackPrivate(key []byte) (PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, ErrKeySize
	}
	priv := s.Scheme.UnpackPrivate(key[:s.Scheme.PrivateKeySize()])
	pub := s.Scheme.UnpackPublic(key[s.Scheme.PrivateKeySize():])
	_, sk := newKeys(nil, &kyberPrivKey{priv, pub, s})
	return sk, nil
}

var _ rawPrivateKey = &kyberPrivKey{}

type kyberPrivKey struct {
	sk  kyber.PrivateKey
	pk  kyber.PublicKey
	sch kyberScheme
}

func (priv *kyberPrivKey) Scheme() crypto.Scheme { return priv.sch }

func (priv *kyberPrivKey) Public() rawPublicKey {
	return &kyberPubKey{priv.pk, priv.sch}
}

func (priv *kyberPrivKey) Pack() []byte {
	buf := make([]byte, priv.sch.PrivateKeySize())
	priv.sk.Pack(buf[:priv.sch.Scheme.PrivateKeySize()])
	priv.pk.Pack(buf[priv.sch.Scheme.PrivateKeySize():])
	return buf
}

func (priv *kyberPrivKey) Equal(p rawPrivateKey) bool {
	pk, ok := p.(*kyberPrivKey)
	return ok && priv.sk.Equal(pk.sk)
}

func (priv *kyberPrivKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != priv.sch.CiphertextSize() {
		return nil, ErrCiphertext
	}
	pt := make([]byte, priv.sch.PlaintextSize())
	priv.sk.DecryptTo(pt, ciphertext)
	return pt, nil
}

var _ rawPublicKey = &kyberPubKey{}

type kyberPubKey struct {
	pk  kyber.PublicKey
	sch kyberScheme
}

func (pub *kyberPubKey) Scheme() crypto.Scheme { return pub.sch }

func (pub *kyberPubKey) Pack() []byte {
	buf := make([]byte, pub.sch.PublicKeySize())
	pub.pk.Pack(buf)
	return buf
}

func (pub *kyberPubKey) Equal(p rawPublicKey) bool {
	pk, ok := p.(*kyberPubKey)
	if !ok {
		return false
	}
	if pub == pk {
		return true
	}
	if pub == nil || pk == nil {
		return false
	}
	if pub.sch.PublicKeySize() != pk.sch.PublicKeySize() {
		return false
	}
	return subtle.ConstantTimeCompare(pub.Pack(), pk.Pack()) == 1
}

func (pub *kyberPubKey) Encrypt(pt, seed []byte) (ciphertext []byte, err error) {
	if len(pt) != pub.sch.PlaintextSize() {
		return nil, ErrPlaintext
	}
	if len(seed) != pub.sch.EncryptionSeedSize() {
		return nil, ErrEncryptionSeed
	}
	ct := make([]byte, pub.sch.CiphertextSize())
	pub.pk.EncryptTo(ct, pt, seed)
	return ct, nil
}
