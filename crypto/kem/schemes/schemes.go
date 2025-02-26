package schemes

import (
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/kem/circl"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(circl.Kyber512)
	Register(circl.Kyber768)
	Register(circl.Kyber1024)
	Register(circl.Frodo640Shake)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (kem.PublicKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (kem.PrivateKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

var schemes = make(scheme.Map[kem.Scheme])

// Register registers a KEM scheme.
func Register(scheme kem.Scheme) { schemes.Register(scheme) }

// ByName returns the KEM scheme by the provided name.
func ByName(name string) (kem.Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered KEM algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered KEM schemes.
func List() []kem.Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (kem.Scheme, error) { return ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[kem.Scheme, Registry]
