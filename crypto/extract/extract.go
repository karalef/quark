package extract

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/scheme"
)

// Scheme represents the master key extraction scheme.
type Scheme interface {
	scheme.Scheme

	// Extract extracts a master key from a low-entropy material and salt and
	// returns a KDF.
	Extract(material, salt []byte) kdf.KDF

	// Expander skips the extraction phase and returns a KDF.
	// The key must have enough entropy to safety skip the extraction.
	Expander(key []byte) kdf.KDF
}

// New creates a new Scheme.
// It does not register the scheme.
func New(name string, ext func(material, salt []byte) kdf.KDF, exp func(prk []byte) kdf.KDF) Scheme {
	return extractor{
		String: scheme.String(name),
		ext:    ext,
		exp:    exp,
	}
}

type extractor struct {
	scheme.String
	ext func(secret, salt []byte) kdf.KDF
	exp func(prk []byte) kdf.KDF
}

func (s extractor) Extract(secret, salt []byte) kdf.KDF { return s.ext(secret, salt) }

func (s extractor) Expander(prk []byte) kdf.KDF { return s.exp(prk) }

// NewSalted creates a new Salted with random salt of length saltSize.
func NewSalted(kdf Scheme, saltSize uint) Salted {
	salt := crypto.Rand(int(saltSize))
	return Salted{
		Scheme: scheme.NewAlgorithm[Scheme, Registry](kdf),
		Salt:   salt,
	}
}

// Salted contains salt and KDF scheme.
type Salted struct {
	Scheme Algorithm `msgpack:"scheme"`

	// Salt is the salt used for the KDF.
	Salt []byte `msgpack:"salt"`
}

// Extract extracts the KDF state from the secret.
func (s Salted) Extract(material []byte) kdf.KDF { return s.Scheme.Scheme.Extract(material, s.Salt) }

// Expander returns a state expander for the provided pseudo-random key.
func (s Salted) Expander(key []byte) kdf.KDF { return s.Scheme.Scheme.Expander(key) }

var kdfs = make(scheme.Map[Scheme])

// Register registers a Scheme.
func Register(scheme Scheme) { kdfs.Register(scheme) }

// ByName returns the Scheme by the provided name.
func ByName(name string) (Scheme, error) { return kdfs.ByName(name) }

// ListNames returns all registered scheme names.
func ListNames() []string { return kdfs.ListNames() }

// List returns all registered scheme schemes.
func List() []Scheme { return kdfs.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }

// Algorithm is an alias for scheme.Algorithm[Scheme, Registry].
type Algorithm = scheme.Algorithm[Scheme, Registry]
