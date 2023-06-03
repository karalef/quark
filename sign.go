package quark

import "github.com/karalef/quark/sign"

// SignScheme represents a signature scheme.
type SignScheme interface {
	Alg() SignAlgorithm
	sign.Scheme
}

// SignAlgorithm represents a signature algorithm.
type SignAlgorithm Algorithm

// signature algorithms.
const (
	// Dilithium2ED25519 hybrids Dilithium mode2 with ed25519
	Dilithium2ED25519 SignAlgorithm = "DILITHIUM2_ED25519"

	// Dilithium3ED448 hybrids Dilithium mode3 with ed448
	Dilithium3ED448 SignAlgorithm = "DILITHIUM3_ED448"

	Dilithium2    SignAlgorithm = "DILITHIUM2"
	Dilithium2AES SignAlgorithm = "DILITHIUM2_AES"
	Dilithium3    SignAlgorithm = "DILITHIUM3"
	Dilithium3AES SignAlgorithm = "DILITHIUM3_AES"
	Dilithium5    SignAlgorithm = "DILITHIUM5"
	Dilithium5AES SignAlgorithm = "DILITHIUM5_AES"

	Falcon1024 SignAlgorithm = "FALCON1024"
	//Rainbow
)

// ListSignSchemes returns all available signature schemes.
func ListSignSchemes() []SignScheme {
	a := make([]SignScheme, 0, len(signSchemes))
	for _, v := range signSchemes {
		a = append(a, v)
	}
	return a
}

// ListSignAlgorithms returns all available signature algorithms.
func ListSignAlgorithms() []SignAlgorithm {
	a := make([]SignAlgorithm, 0, len(signSchemes))
	for alg := range signSchemes {
		a = append(a, alg)
	}
	return a
}

type signScheme struct {
	SignAlgorithm
	sign.Scheme
}

var signSchemes = map[SignAlgorithm]signScheme{
	Dilithium2ED25519: {Dilithium2ED25519, sign.EDDilithium2()},
	Dilithium3ED448:   {Dilithium3ED448, sign.EDDilithium3()},
	Dilithium2:        {Dilithium2, sign.Dilithium2()},
	Dilithium2AES:     {Dilithium2AES, sign.Dilithium2AES()},
	Dilithium3:        {Dilithium3, sign.Dilithium3()},
	Dilithium3AES:     {Dilithium3AES, sign.Dilithium3AES()},
	Dilithium5:        {Dilithium5, sign.Dilithium5()},
	Dilithium5AES:     {Dilithium5AES, sign.Dilithium5AES()},
	Falcon1024:        {Falcon1024, sign.Falcon1024()},
}

// Alg returns itself.
func (alg SignAlgorithm) Alg() SignAlgorithm { return alg }

// Scheme returns the signature scheme.
// Returns nil if the algorithm is invalid or unsupported.
func (alg SignAlgorithm) Scheme() SignScheme { return signSchemes[alg] }

// IsValid returns true if the algorithm is valid and supported.
func (alg SignAlgorithm) IsValid() bool { return alg.Scheme() != nil }

func (alg SignAlgorithm) String() string {
	if !alg.IsValid() {
		alg = SignAlgorithm(InvalidAlgorithm)
	}
	return string(alg)
}
