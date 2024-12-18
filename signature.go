package quark

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
)

// Signable represents an object that can be signed.
type Signable interface {
	SignEncode(io.Writer) error
}

// SignObject signs the object.
func SignObject(sk sign.PrivateKey, v Validity, obj Signable) (Signature, error) {
	signer := Sign(sk)
	if err := obj.SignEncode(signer); err != nil {
		return Signature{}, err
	}
	return signer.Sign(v)
}

// Sign creates a Signer.
func Sign(sk sign.PrivateKey) *Signer {
	return &Signer{
		Signer: sk.Sign(),
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
	v.SignEncode(s.Signer)
	s.sig.Validity = v
	s.sig.Signature = s.Signer.Sign()
	return s.sig, nil
}

// ErrUnixNegative is returned when the unix time is negative.
var ErrUnixNegative = errors.New("unix time is negative")

// EncodeTime encodes a unix time into a byte slice.
// Panics if time is negative.
func EncodeTime(time int64) []byte {
	if time < 0 {
		panic(ErrUnixNegative)
	}
	var binTime [binary.MaxVarintLen64]byte
	return binTime[:binary.PutVarint(binTime[:], time)]
}

// Signature represents a signature.
type Signature struct {
	Signature []byte             `msgpack:"sig"`
	Validity  Validity           `msgpack:"validity"`
	Issuer    crypto.Fingerprint `msgpack:"issuer"`
}

// IsRevoked returns true if the signature is revoked.
func (s Signature) IsRevoked() bool { return s.Validity.IsRevoked() }

// Copy returns a copy of the signature.
func (s Signature) Copy() Signature {
	s.Signature = crypto.Copy(s.Signature)
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

// VerifyObject verifies the signature.
func (s Signature) VerifyObject(pk sign.PublicKey, obj Signable) (bool, error) {
	verifier := Verify(pk)
	if err := obj.SignEncode(verifier); err != nil {
		return false, err
	}
	return verifier.Verify(s)
}

// Verify creates a Verifier.
// It is used if the signature is not available before the message is read.
func Verify(pk sign.PublicKey) *Verifier { return &Verifier{pk.Verify()} }

// Verifier represents a signature verification state.
type Verifier struct{ sign.Verifier }

// Verify checks whether the given signature is a valid signature set by
// the private key corresponding to the specified public key on the
// written message.
// Returns an error if the signature does not match the scheme.
func (v *Verifier) Verify(sig Signature) (bool, error) {
	if err := sig.Validate(); err != nil {
		return false, err
	}
	sig.Validity.SignEncode(v.Verifier)
	return v.Verifier.Verify(sig.Signature)
}

// NewValidity creates a new Validity.
// Panics if the validity has incorrect values.
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
	Created int64 `msgpack:"created"`
	// expiration time
	Expires int64 `msgpack:"expires,omitempty"`
}

// SignEncode writes the validity to the sign writer.
//
//nolint:errcheck
func (v Validity) SignEncode(w io.Writer) {
	w.Write(EncodeTime(v.Created))
	w.Write(EncodeTime(v.Expires))
	w.Write(EncodeTime(v.Revoked))
	io.WriteString(w, v.Reason)
}

// IsRevoked returns true if the validity is revoked.
func (v Validity) IsRevoked() bool { return v.Revoked > 0 || v.Reason != "" }

// IsExpired returns true if the validity is expired.
func (v Validity) IsExpired(t int64) bool { return v.Expires > 0 && v.Expires <= t }

// IsValid returns true if the validity neither expired nor revoked.
func (v Validity) IsValid(t int64) bool { return !v.IsRevoked() && !v.IsExpired(t) }

// Revokes returns the revoked copy of the signature.
// Does nothing is the validity is already revoked.
func (v Validity) Revoke(t int64, reason string) Validity {
	if !v.IsRevoked() {
		v.Revoked = t
		v.Reason = reason
	}
	return v
}

// Validate returns an error if the validity has incorrect values.
func (v Validity) Validate() error {
	if v.Created < 0 || v.Expires < 0 || v.Revoked < 0 {
		return ErrUnixNegative
	} else if v.Expires > 0 && v.Expires < v.Created {
		return errors.New("invalid expiration time")
	} else if v.Revoked > 0 && v.Revoked < v.Created {
		return errors.New("invalid revocation time")
	}
	return nil
}

// validity errors.
var (
	ErrExpired          = errors.New("signature is expired")
	ErrRevoked          = errors.New("signature is revoked")
	ErrExpiredOrRevoked = errors.New("signature is expired or revoked")
)
