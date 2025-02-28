package sign

import (
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/karalef/quark/crypto/sign/circl"
	"github.com/karalef/quark/crypto/sign/falcon1024"
	"github.com/karalef/quark/scheme"
)

var (
	// Falcon1024 is the falcon1024 signature scheme.
	Falcon1024 = falcon1024.Scheme

	// MLDSA44 is the ML-DSA-44 signature scheme.
	MLDSA44 = circl.New("MLDSA44", mldsa44.Scheme())

	// MLDSA65 is the ML-DSA-65 signature scheme.
	MLDSA65 = circl.New("MLDSA65", mldsa65.Scheme())

	// MLDSA87 is the ML-DSA-87 signature scheme.
	MLDSA87 = circl.New("MLDSA87", mldsa87.Scheme())

	// ED25519Dilithium2 is the hybrid signature scheme of ED25519 and Dilithium in mode 2.
	ED25519Dilithium2 = circl.New("ED25519_Dilithium2", eddilithium2.Scheme())

	// ED448Dilithium3 is the hybrid signature scheme of ED448 and Dilithium in mode 3.
	ED448Dilithium3 = circl.New("ED448_Dilithium3", eddilithium3.Scheme())
)

func init() {
	Register(Falcon1024)
	Register(MLDSA44)
	Register(MLDSA65)
	Register(MLDSA87)
	Register(ED25519Dilithium2)
	Register(ED448Dilithium3)
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

// Register registers a signature scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the signature scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered signature algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered signature schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
