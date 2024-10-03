package sign

import (
	"io"
)

// StreamPrivateKey represents a private key supporting streaming signatures.
type StreamPrivateKey interface {
	PrivateKey
	Signer() Signer
}

// StreamPublicKey represents a public key supporting streaming signatures.
type StreamPublicKey interface {
	PublicKey
	Verifier() Verifier
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
