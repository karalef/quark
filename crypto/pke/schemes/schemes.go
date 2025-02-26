package schemes

import (
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/pke/kyber"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(kyber.Kyber512)
	Register(kyber.Kyber768)
	Register(kyber.Kyber1024)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (pke.PublicKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (pke.PrivateKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

var schemes = make(scheme.Map[pke.Scheme])

// Register registers a PKE scheme.
func Register(scheme pke.Scheme) { schemes.Register(scheme) }

// ByName returns the PKE scheme by the provided name.
func ByName(name string) (pke.Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered PKE algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered PKE schemes.
func List() []pke.Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (pke.Scheme, error) { return ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[pke.Scheme, Registry]
