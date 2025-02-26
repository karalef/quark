package schemes

import (
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/sign/eddilithium"
	"github.com/karalef/quark/crypto/sign/falcon1024"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(falcon1024.Scheme)
	Register(eddilithium.ED25519Mode2)
	Register(eddilithium.ED448Mode3)
}

// UnpackPublic unpacks a public key from the provided scheme name and key material.
func UnpackPublic(schemeName string, key []byte) (sign.PublicKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPublic(key)
}

// UnpackPrivate unpacks a private key from the provided scheme name and key material.
func UnpackPrivate(schemeName string, key []byte) (sign.PrivateKey, error) {
	scheme, err := ByName(schemeName)
	if err != nil {
		return nil, err
	}
	return scheme.UnpackPrivate(key)
}

var schemes = make(scheme.Map[sign.Scheme])

// Register registers a signature scheme.
func Register(scheme sign.Scheme) { schemes.Register(scheme) }

// ByName returns the signature scheme by the provided name.
func ByName(name string) (sign.Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered signature algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered signature schemes.
func List() []sign.Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (sign.Scheme, error) { return ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[sign.Scheme, Registry]
