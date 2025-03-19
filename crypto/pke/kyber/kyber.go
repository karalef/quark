package kyber

import (
	"github.com/cloudflare/circl/pke/kyber/kyber1024"
	"github.com/cloudflare/circl/pke/kyber/kyber512"
	"github.com/cloudflare/circl/pke/kyber/kyber768"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/pke/internal"
	"github.com/karalef/quark/scheme"
)

var _ internal.Scheme = kyberScheme[*kyber512.PublicKey, *kyber512.PrivateKey]{}

type kyberScheme[PK kyberPublicKey, SK kyberPrivateKey[SK]] struct {
	scheme.String
	derive  func(seed []byte) (PK, SK)
	public  func([]byte) PK
	private func([]byte) SK
	sk, pk  int
	ct, pt  int
	es, s   int
}

func (s kyberScheme[PK, SK]) DeriveKey(seed []byte) (internal.PublicKey, internal.PrivateKey) {
	if len(seed) != s.s {
		panic(internal.ErrSeedSize)
	}
	pk, sk := s.derive(seed)
	pub := kyberPubKey{pk: pk, scheme: s}
	return pub, kyberPrivKey[SK]{sk, pub}
}

func (s kyberScheme[_, SK]) UnpackPrivate(key []byte) (internal.PrivateKey, error) {
	if len(key) != s.PrivateKeySize() {
		return nil, internal.ErrKeySize
	}
	pub := kyberPubKey{pk: s.public(key[:s.pk]), scheme: s}
	return kyberPrivKey[SK]{s.private(key[s.pk:]), pub}, nil
}

func (s kyberScheme[PK, _]) UnpackPublic(key []byte) (internal.PublicKey, error) {
	if len(key) != s.PublicKeySize() {
		return nil, internal.ErrKeySize
	}
	return kyberPubKey{pk: s.public(key), scheme: s}, nil
}

func (s kyberScheme[_, _]) Size() int               { return s.ct }
func (s kyberScheme[_, _]) PlaintextSize() int      { return s.pt }
func (s kyberScheme[_, _]) EncryptionSeedSize() int { return s.es }
func (s kyberScheme[_, _]) PrivateKeySize() int     { return s.sk + s.pk }
func (s kyberScheme[_, _]) PublicKeySize() int      { return s.pk }
func (s kyberScheme[_, _]) SeedSize() int           { return s.s }

type kyberPublicKey interface {
	EncryptTo(ct []byte, pt []byte, seed []byte)
	Pack(buf []byte)
	Unpack(buf []byte)
}

type kyberPrivateKey[T any] interface {
	DecryptTo(pt []byte, ct []byte)
	Equal(other T) bool
	Pack(buf []byte)
	Unpack(buf []byte)
}

var _ internal.PublicKey = &kyberPubKey{}

type kyberPubKey struct {
	pk     kyberPublicKey
	scheme internal.Scheme
}

func (k kyberPubKey) Scheme() internal.Scheme { return k.scheme }

func (k kyberPubKey) Pack() []byte {
	buf := make([]byte, k.scheme.PublicKeySize())
	k.pk.Pack(buf)
	return buf
}

func (k kyberPubKey) Equal(other internal.PublicKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(kyberPubKey)
	return ok && k.scheme.PublicKeySize() == o.scheme.PublicKeySize() &&
		crypto.Equal(k.Pack(), o.Pack())
}

func (k kyberPubKey) Encrypt(plaintext []byte, seed []byte) ([]byte, error) {
	if len(seed) != k.scheme.EncryptionSeedSize() {
		panic(internal.ErrSeedSize)
	}
	if len(plaintext) != k.scheme.PlaintextSize() {
		return nil, internal.ErrPlaintext
	}
	ct := make([]byte, k.scheme.Size())
	k.pk.EncryptTo(ct, plaintext, seed)
	return ct, nil
}

var _ internal.PrivateKey = kyberPrivKey[*kyber512.PrivateKey]{}

type kyberPrivKey[T any] struct {
	sk kyberPrivateKey[T]
	pk kyberPubKey
}

func (k kyberPrivKey[_]) Scheme() internal.Scheme    { return k.pk.scheme }
func (k kyberPrivKey[_]) Public() internal.PublicKey { return k.pk }

func (k kyberPrivKey[T]) Pack() []byte {
	buf := make([]byte, k.pk.scheme.PrivateKeySize())
	pk := k.pk.scheme.PublicKeySize()
	k.pk.pk.Pack(buf[:pk])
	k.sk.Pack(buf[pk:])
	return buf
}

func (k kyberPrivKey[T]) Equal(other internal.PrivateKey) bool {
	if other == nil {
		return false
	}
	o, ok := other.(kyberPrivKey[T])
	if !ok {
		return false
	}
	if o, ok := o.sk.(T); ok {
		return k.sk.Equal(o)
	}
	return false
}

func (k kyberPrivKey[T]) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != k.pk.scheme.Size() {
		return nil, internal.ErrCiphertext
	}
	pt := make([]byte, k.pk.scheme.PlaintextSize())
	k.sk.DecryptTo(pt, ciphertext)
	return pt, nil
}

var Kyber512 = kyberScheme[*kyber512.PublicKey, *kyber512.PrivateKey]{
	String: "Kyber512",
	derive: kyber512.NewKeyFromSeed,
	public: func(b []byte) *kyber512.PublicKey {
		var pk kyber512.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber512.PrivateKey {
		var sk kyber512.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber512.PrivateKeySize,
	pk: kyber512.PublicKeySize,
	ct: kyber512.CiphertextSize,
	pt: kyber512.PlaintextSize,
	es: kyber512.EncryptionSeedSize,
	s:  kyber512.KeySeedSize,
}

var Kyber768 = kyberScheme[*kyber768.PublicKey, *kyber768.PrivateKey]{
	String: "Kyber768",
	derive: kyber768.NewKeyFromSeed,
	public: func(b []byte) *kyber768.PublicKey {
		var pk kyber768.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber768.PrivateKey {
		var sk kyber768.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber768.PrivateKeySize,
	pk: kyber768.PublicKeySize,
	ct: kyber768.CiphertextSize,
	pt: kyber768.PlaintextSize,
	es: kyber768.EncryptionSeedSize,
	s:  kyber768.KeySeedSize,
}

var Kyber1024 = kyberScheme[*kyber1024.PublicKey, *kyber1024.PrivateKey]{
	String: "Kyber1024",
	derive: kyber1024.NewKeyFromSeed,
	public: func(b []byte) *kyber1024.PublicKey {
		var pk kyber1024.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber1024.PrivateKey {
		var sk kyber1024.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber1024.PrivateKeySize,
	pk: kyber1024.PublicKeySize,
	ct: kyber1024.CiphertextSize,
	pt: kyber1024.PlaintextSize,
	es: kyber1024.EncryptionSeedSize,
	s:  kyber1024.KeySeedSize,
}
