package kem

import "github.com/karalef/quark/crypto"

type rawKey interface {
	Scheme() crypto.Scheme
	Pack() []byte
}

type rawPublicKey interface {
	rawKey
	Equal(rawPublicKey) bool
	Encapsulate(seed []byte) (ciphertext, secret []byte, err error)
}

type rawPrivateKey interface {
	rawKey
	Public() rawPublicKey
	Equal(rawPrivateKey) bool
	Decapsulate(ciphertext []byte) ([]byte, error)
}

func newPub(r rawPublicKey) *publicKey {
	return &publicKey{crypto.NewKeyID(r)}
}

func newKeys(pk rawPublicKey, sk rawPrivateKey) (PublicKey, PrivateKey) {
	if pk == nil {
		if sk == nil {
			return nil, nil
		}
		pk = sk.Public()
	}
	pub := newPub(pk)
	if sk == nil {
		return pub, nil
	}
	return pub, &privateKey{
		rawPrivateKey: sk,
		pub:           pub,
	}
}

var _ PublicKey = &publicKey{}

type publicKey struct {
	crypto.KeyID[rawPublicKey]
}

func (k publicKey) Encapsulate(seed []byte) (ciphertext, secret []byte, err error) {
	return k.PublicKey.Encapsulate(seed)
}

func (k *publicKey) Equal(pk PublicKey) bool {
	if pk == nil {
		return false
	}
	p, ok := pk.(*publicKey)
	if !ok {
		return false
	}
	if k == p { // the same pointer
		return true
	}
	if k == nil || p == nil {
		return false
	}
	return k.PublicKey.Equal(p.PublicKey)
}

func (k *publicKey) CorrespondsTo(priv PrivateKey) bool {
	if priv == nil {
		return false
	}
	return k.Equal(priv.Public())
}

var _ PrivateKey = &privateKey{}

type privateKey struct {
	rawPrivateKey
	pub *publicKey
}

func (k *privateKey) Public() PublicKey               { return k.pub }
func (k *privateKey) ID() crypto.ID                   { return k.pub.ID() }
func (k *privateKey) Fingerprint() crypto.Fingerprint { return k.pub.Fingerprint() }
func (k *privateKey) Equal(sk PrivateKey) bool {
	if sk == nil {
		return false
	}
	s, ok := sk.(*privateKey)
	if !ok {
		return false
	}
	if k == s { // the same pointer
		return true
	}
	if k == nil || s == nil {
		return false
	}
	return k.rawPrivateKey.Equal(s.rawPrivateKey)
}
