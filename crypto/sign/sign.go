package sign

import (
	"github.com/karalef/quark/crypto/sign/internal"
)

// Scheme represents signature scheme.
type Scheme = internal.Scheme

// PrivateKey represents a signing private key.
type PrivateKey = internal.PrivateKey

// PublicKey represents a signing public key.
type PublicKey = internal.PublicKey

// Signer represents a signature state.
type Signer = internal.Signer

// Verifier represents a signature verification state.
type Verifier = internal.Verifier

// ErrSignature is returned when the signature does not match the scheme.
var ErrSignature = internal.ErrSignature

// ErrSeedSize is an error with which the DeriveKey method panics.
var ErrSeedSize = internal.ErrSeedSize

// ErrKeySize is returned when the key size does not match the scheme.
var ErrKeySize = internal.ErrKeySize
