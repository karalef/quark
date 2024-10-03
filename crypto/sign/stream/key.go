package stream

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/scheme"
)

// PrivateKey returns a StreamPrivateKey that uses the provided hash function.
// If priv implements StreamPrivateKey, the hash function is ignored.
// If hash is nil, uses NewBuffer(0) to provide streaming.
func PrivateKey(priv sign.PrivateKey, hash hash.Scheme) sign.StreamPrivateKey {
	if sk, ok := priv.(sign.StreamPrivateKey); ok {
		return sk
	}
	return &streamPrivateKey{priv, hash}
}

// PublicKey returns a StreamPublicKey that uses the provided hash function.
// If pub implements StreamPublicKey, the hash function is ignored.
// If hash is nil, uses NewBuffer(0) to provide streaming.
func PublicKey(pub sign.PublicKey, hash hash.Scheme) sign.StreamPublicKey {
	if pk, ok := pub.(sign.StreamPublicKey); ok {
		return pk
	}
	return &streamPublicKey{pub, hash}
}

type streamPrivateKey struct {
	sign.PrivateKey
	hash hash.Scheme
}

func (s *streamPrivateKey) Signer() sign.Signer {
	return &streamSigner{s.hash.New(), s.PrivateKey}
}

type streamPublicKey struct {
	sign.PublicKey
	hash hash.Scheme
}

func (s *streamPublicKey) Verifier() sign.Verifier {
	return &streamVerifier{s.hash.New(), s.PublicKey}
}

type streamScheme struct {
	sign.Scheme
	hash hash.Scheme
}

func (s streamScheme) Name() string {
	return scheme.Join(s.Scheme, s.hash)
}

// DeriveKey derives a key-pair from a seed.
func (s streamScheme) DeriveKey(seed []byte) (sign.StreamPrivateKey, sign.StreamPublicKey, error)

// Unpacks a StreamPublicKey from the provided bytes.
func (s streamScheme) UnpackPublic(key []byte) (sign.StreamPublicKey, error)

// Unpacks a StreamPrivateKey from the provided bytes.
func (s streamScheme) UnpackPrivate(key []byte) (sign.StreamPrivateKey, error)

// Build creates a stream sign scheme.
// Panics if one of the arguments is nil.
func Build(sign sign.Scheme, hash hash.Scheme) Scheme {
	if cipher == nil || mac == nil {
		panic("nil scheme part")
	}
	return &baseScheme{
		StringName: scheme.StringName(scheme.Join(cipher, mac)),
		cipher:     cipher,
		mac:        mac,
	}
}

// FromName creates an AEAD scheme from its name.
func FromName(schemeName string) (Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 2)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1])
}

// FromNames creates an AEAD scheme from its part names.
func FromNames(cipherName, macName string) (Scheme, error) {
	cipher, err := cipher.ByName(cipherName)
	if err != nil {
		return nil, err
	}
	mac, err := mac.ByName(macName)
	if err != nil {
		return nil, err
	}
	return Build(cipher, mac), nil
}
