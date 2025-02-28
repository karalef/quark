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
	Register(Kyber512)
	Register(Kyber768)
	Register(Kyber1024)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (PublicKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (PrivateKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

var schemes = make(scheme.Map[Scheme])

// Register registers a PKE scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the PKE scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered PKE algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered PKE schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
