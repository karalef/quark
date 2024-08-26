package kem

import "github.com/karalef/quark/crypto"

type rawKey interface {
	Scheme() Scheme
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
	return &publicKey{rawPublicKey: r}
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
	rawPublicKey
	id crypto.ID
	fp crypto.Fingerprint
}

func (k *publicKey) ID() crypto.ID {
	if k.id.IsEmpty() {
		k.id = k.Fingerprint().ID()
	}
	return k.id
}

func (k *publicKey) Fingerprint() crypto.Fingerprint {
	if k.fp.IsEmpty() {
		k.fp = crypto.CalculateFingerprint(k.Scheme().Name(), k.Pack())
	}
	return k.fp
}

func (k *publicKey) Equal(pk PublicKey) bool {
	if pk == nil {
		return false
	}
	p, ok := pk.(*publicKey)
	if !ok {
		return false
	}
	return k.rawPublicKey.Equal(p.rawPublicKey)
}

func (k *publicKey) CorrespondsTo(priv PrivateKey) bool {
	sk, ok := priv.(*privateKey)
	if !ok {
		return false
	}
	// the same pointer
	if k == sk.pub {
		return true
	}

	return k.rawPublicKey.Equal(sk.pub.rawPublicKey)
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
	return k.rawPrivateKey.Equal(s.rawPrivateKey)
}
