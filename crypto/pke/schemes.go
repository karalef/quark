package pke

import (
	"github.com/karalef/quark/crypto/pke/kyber"
	"github.com/karalef/quark/scheme"
)

var (
	// Kyber512 is the Kyber-512 PKE scheme.
	Kyber512 = kyber.Kyber512

	// Kyber768 is the Kyber-768 PKE scheme.
	Kyber768 = kyber.Kyber768

	// Kyber1024 is the Kyber-1024 PKE scheme.
	Kyber1024 = kyber.Kyber1024
)

func init() {
	Schemes.Register(Kyber512)
	Schemes.Register(Kyber768)
	Schemes.Register(Kyber1024)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (PublicKey, error) {
	scheme, err := Schemes.ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (PrivateKey, error) {
	scheme, err := Schemes.ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

// Schemes is a registry of PKE schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
