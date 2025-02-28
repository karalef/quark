package internal

import (
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
)

// Scheme represents signature scheme.
type Scheme crypto.KeyScheme[PublicKey, PrivateKey]

// PrivateKey represents a signing private key.
type PrivateKey interface {
	crypto.PrivateKey[Scheme, PrivateKey, PublicKey]

	// Sign signs the message.
	Sign() Signer
}

// PublicKey represents a signing public key.
type PublicKey interface {
	crypto.PublicKey[Scheme, PublicKey]

	// Verify verifies the signature created by this key.
	Verify() Verifier
}

// Signer represents a signature state.
type Signer interface {
	io.Writer

	// Reset resets the Signer.
	Reset()

	// Sign signs the written message and returns the signature.
	Sign() []byte
}

// Verifier represents a signature verification state.
type Verifier interface {
	io.Writer

	// Reset resets the Verifier.
	Reset()

	// Verify checks whether the given signature is a valid signature set by
	// the private key corresponding to the specified public key on the
	// written message.
	// Returns an error if the signature does not match the scheme.
	Verify(signature []byte) (bool, error)
}

// ErrSignature is returned when the signature does not match the scheme.
var ErrSignature = errors.New("invalid signature")

// ErrSeedSize is an error with which the DeriveKey method panics.
var ErrSeedSize = errors.New("invalid seed size")

// ErrKeySize is returned when the key size does not match the scheme.
var ErrKeySize = errors.New("invalid key size")
