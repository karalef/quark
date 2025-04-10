package kem

import (
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/karalef/quark/crypto/kem/circl"
	"github.com/karalef/quark/scheme"
)

// kem schemes.
var (
	// MLKEM512 is the ML-KEM-512 signature scheme.
	MLKEM512 = circl.New("MLKEM512", mlkem512.Scheme())

	// MLKEM768 is the ML-KEM-768 signature scheme.
	MLKEM768 = circl.New("MLKEM768", mlkem768.Scheme())

	// MLKEM1024 is the ML-KEM-1024 signature scheme.
	MLKEM1024 = circl.New("MLKEM1024", mlkem1024.Scheme())

	// Kyber512 is the Kyber-512 signature scheme.
	Kyber512 = circl.New("Kyber512", kyber512.Scheme())

	// Kyber768 is the Kyber-768 signature scheme.
	Kyber768 = circl.New("Kyber768", kyber768.Scheme())

	// Kyber1024 is the Kyber-1024 signature scheme.
	Kyber1024 = circl.New("Kyber1024", kyber1024.Scheme())

	// Frodo640Shake is the FrodoKEM-640 with SHAKE signature scheme.
	Frodo640Shake = circl.New("Frodo640SHAKE", frodo640shake.Scheme())

	// Kyber512X25519 is the hybrid KEM of Kyber-512 and X25519 signature schemes.
	Kyber512X25519 = circl.New("Kyber512_X25519", hybrid.Kyber512X25519())

	// Kyber768X25519 is the hybrid KEM of Kyber-768 and X25519 signature schemes.
	Kyber768X25519 = circl.New("Kyber768_X25519", hybrid.Kyber768X25519())

	// Kyber768X448 is the hybrid KEM of Kyber-768 and X448 signature schemes.
	Kyber768X448 = circl.New("Kyber768_X448", hybrid.Kyber768X448())

	// Kyber1024X448 is the hybrid KEM of Kyber-1024 and X448 signature schemes.
	Kyber1024X448 = circl.New("Kyber1024_X448", hybrid.Kyber1024X448())

	// X25519MLKEM768 is the hybrid KEM of X25519 and ML-KEM-768 signature schemes.
	X25519MLKEM768 = circl.New("X25519_MLKEM768", hybrid.X25519MLKEM768())
)

func init() {
	Schemes.Register(MLKEM512)
	Schemes.Register(MLKEM768)
	Schemes.Register(MLKEM1024)
	Schemes.Register(Kyber512)
	Schemes.Register(Kyber768)
	Schemes.Register(Kyber1024)
	Schemes.Register(Frodo640Shake)
	Schemes.Register(Kyber512X25519)
	Schemes.Register(Kyber768X25519)
	Schemes.Register(Kyber768X448)
	Schemes.Register(Kyber1024X448)
	Schemes.Register(X25519MLKEM768)
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

// Schemes is a registry of KEM schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }

// Algorithm is a typed scheme.Algorithm.
type Algorithm = scheme.Algorithm[Scheme, Registry]
