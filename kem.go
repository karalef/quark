package quark

import (
	"github.com/karalef/quark/cipher"
	"github.com/karalef/quark/kem"
)

func init() {
	for a, scheme := range kemSchemes {
		if scheme.SharedSecretSize() != scheme.Cipher().KeySize() {
			panic("invalid kem algorithm (" + a + "): shared key size mismatch")
		}
	}
}

// KEMScheme represents a KEM scheme.
type KEMScheme interface {
	Alg() KEMAlgorithm
	kem.Scheme
	Cipher() cipher.Scheme
}

// KEMAlgorithm represents KEM algorithm.
type KEMAlgorithm Algorithm

// available KEM algorithms.
const (
	Kyber512AESGCM            KEMAlgorithm = "KYBER512-AES_GCM"
	Kyber512XChaCha20Poly1305 KEMAlgorithm = "KYBER512-XCHACHA20_POLY1305"

	Kyber768AESGCM            KEMAlgorithm = "KYBER768-AES_GCM"
	Kyber768XChaCha20Poly1305 KEMAlgorithm = "KYBER768-XCHACHA20_POLY1305"

	Kyber1024AESGCM            KEMAlgorithm = "KYBER1024-AES_GCM"
	Kyber1024XChaCha20Poly1305 KEMAlgorithm = "KYBER1024-XCHACHA20_POLY1305"

	Frodo640ShakeAESGCM KEMAlgorithm = "FRODO640SHAKE-AES_GCM"
)

// ListKEMSchemes returns all available KEM schemes.
func ListKEMSchemes() []KEMScheme {
	a := make([]KEMScheme, 0, len(kemSchemes))
	for _, v := range kemSchemes {
		a = append(a, v)
	}
	return a
}

// ListKEMAlgorithms returns all available KEM algorithms.
func ListKEMAlgorithms() []KEMAlgorithm {
	a := make([]KEMAlgorithm, 0, len(kemSchemes))
	for alg := range kemSchemes {
		a = append(a, alg)
	}
	return a
}

type kemScheme struct {
	KEMAlgorithm
	kem.Scheme
	cipher cipher.Scheme
}

// Cipher returns the cipher scheme.
func (s kemScheme) Cipher() cipher.Scheme { return s.cipher }

var kemSchemes = map[KEMAlgorithm]kemScheme{
	Kyber512AESGCM:             kemScheme{Kyber512AESGCM, kem.Kyber512(), cipher.AESGCM256()},
	Kyber512XChaCha20Poly1305:  kemScheme{Kyber512XChaCha20Poly1305, kem.Kyber512(), cipher.XChaCha20Poly1305()},
	Kyber768AESGCM:             kemScheme{Kyber768AESGCM, kem.Kyber768(), cipher.AESGCM256()},
	Kyber768XChaCha20Poly1305:  kemScheme{Kyber768XChaCha20Poly1305, kem.Kyber768(), cipher.XChaCha20Poly1305()},
	Kyber1024AESGCM:            kemScheme{Kyber1024AESGCM, kem.Kyber1024(), cipher.AESGCM256()},
	Kyber1024XChaCha20Poly1305: kemScheme{Kyber1024XChaCha20Poly1305, kem.Kyber1024(), cipher.XChaCha20Poly1305()},
	Frodo640ShakeAESGCM:        kemScheme{Frodo640ShakeAESGCM, kem.Frodo640Shake(), cipher.AESGCM128()},
}

// Alg returns itself.
func (alg KEMAlgorithm) Alg() KEMAlgorithm { return alg }

// Scheme returns the KEM scheme.
// Returns nil if the algorithm is invalid or unsupported.
func (alg KEMAlgorithm) Scheme() KEMScheme { return kemSchemes[alg] }

// IsValid returns true if the algorithm is valid and supported.
func (alg KEMAlgorithm) IsValid() bool { return alg.Scheme() != nil }

func (alg KEMAlgorithm) String() string {
	if !alg.IsValid() {
		alg = KEMAlgorithm(InvalidAlgorithm)
	}
	return string(alg)
}
