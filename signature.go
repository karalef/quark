package quark

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/internal"
)

// Sign signs the message.
func Sign(sk PrivateKey, v Validity, message []byte) (Signature, error) {
	signer := SignStream(sk)
	signer.Write(message)
	return signer.Sign(v)
}

// SignStream creates a Signer.
func SignStream(sk PrivateKey) *Signer {
	signer := sign.StreamSigner(sk, nil)
	signer.Write(sk.Fingerprint().Bytes())

	return &Signer{
		Signer: signer,
		sig: Signature{
			Issuer: sk.Fingerprint(),
		},
	}
}

// Signer represents a signature state.
type Signer struct {
	sign.Signer
	sig Signature
}

// Reset resets the Signer state except the issuer and validity.
func (s *Signer) Reset() {
	s.sig.Signature = nil
	s.Signer.Reset()
}

// Sign signs the written message and returns the signature.
func (s *Signer) Sign(v Validity) (Signature, error) {
	if err := v.Validate(); err != nil {
		return Signature{}, err
	}
	v.signEncode(s.Signer)
	s.sig.Validity = v
	s.sig.Signature = s.Signer.Sign()
	return s.sig, nil
}

// MarshalTime encodes a unix time into a byte array.
func MarshalTime(time int64) []byte {
	var binTime [8]byte
	binary.LittleEndian.PutUint64(binTime[:], uint64(time))
	return binTime[:]
}

// Signature represents a signature.
type Signature struct {
	Signature []byte      `msgpack:"sig"`
	Validity  Validity    `msgpack:"validity"`
	Issuer    Fingerprint `msgpack:"issuer"`
}

// Copy returns a copy of the signature.
func (s Signature) Copy() Signature {
	s.Signature = internal.Copy(s.Signature)
	return s
}

// Validate returns an error if the signature has incorrect values.
func (s Signature) Validate() error {
	if err := s.Validity.Validate(); err != nil {
		return errors.Join(errors.New("invalid signature validity"), err)
	}
	switch {
	case s.Issuer.IsEmpty():
		return errors.New("invalid signature (no issuer)")
	case len(s.Signature) == 0:
		return errors.New("invalid signature (no signature)")
	default:
		return nil
	}
}

// Verify verifies the signature.
func (s Signature) Verify(pk PublicKey, message []byte) (bool, error) {
	verifier := VerifyStream(pk)
	verifier.Write(message)
	return verifier.Verify(s)
}

// VerifyStream creates a Verifier.
// It is used if the signature is not available before the message is read.
func VerifyStream(pk PublicKey) *Verifier {
	verifier := sign.StreamVerifier(pk, nil)
	verifier.Write(pk.Fingerprint().Bytes())
	return &Verifier{verifier}
}

// Verifier represents a signature verification state.
type Verifier struct {
	sign.Verifier
}

// Verify checks whether the given signature is a valid signature set by
// the private key corresponding to the specified public key on the
// written message.
// Returns an error if the signature does not match the scheme.
func (v *Verifier) Verify(sig Signature) (bool, error) {
	if err := sig.Validate(); err != nil {
		return false, err
	}
	sig.Validity.signEncode(v.Verifier)
	return v.Verifier.Verify(sig.Signature)
}

// NewValidity creates a new Validity.
func NewValidity(created, expires int64) Validity {
	v := Validity{
		Created: created,
		Expires: expires,
	}
	if err := v.Validate(); err != nil {
		panic(err)
	}
	return v
}

// Validity contains the signature validity.
type Validity struct {
	// revocation reason
	Reason string `msgpack:"reason,omitempty"`
	// revocation time
	Revoked int64 `msgpack:"revoked,omitempty"`
	// creation time
	Created int64 `msgpack:"created,omitempty"`
	// expiration time
	Expires int64 `msgpack:"expires,omitempty"`
}

func (v Validity) signEncode(w io.Writer) error {
	_, err := io.WriteString(w, v.Reason)
	if err != nil {
		return err
	}
	_, err = w.Write(MarshalTime(v.Revoked))
	if err != nil {
		return err
	}
	_, err = w.Write(MarshalTime(v.Created))
	if err != nil {
		return err
	}
	_, err = w.Write(MarshalTime(v.Expires))
	return err
}

// IsRevoked returns true if the validity is revoked.
func (v Validity) IsRevoked(t int64) bool { return v.Revoked > 0 && v.Revoked <= t || v.Reason != "" }

// IsExpired returns true if the validity is expired.
func (v Validity) IsExpired(t int64) bool { return v.Expires > 0 && v.Expires <= t }

// Revoke returns a revoked copy of the validity.
func (v Validity) Revoke(t int64, reason string) Validity {
	v.Revoked = t
	v.Reason = reason
	return v
}

// Validate returns an error if the validity has incorrect values.
func (v Validity) Validate() error {
	switch {
	case v.Created < 0 || v.Expires < 0 || v.Revoked < 0:
		return errors.New("unix time is negative")
	case v.Expires > 0 && v.Expires < v.Created:
		return errors.New("invalid expiration time")
	case v.Revoked > 0 && v.Revoked < v.Created:
		return errors.New("invalid revocation time")
	default:
		return nil
	}
}
