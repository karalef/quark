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
	err := obj.SignEncode(signer)
	if err != nil {
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
	Validity  Validity           `msgpack:"validity"`
	Signature []byte             `msgpack:"sig"`
	Issuer    crypto.Fingerprint `msgpack:"issuer"`
}

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
	err := obj.SignEncode(verifier)
	if err != nil {
		return false, err
	}
	return verifier.Verify(s)
}

// Verify creates a Verifier.
// It is used if the signature is not available before the message is read.
func Verify(pk sign.PublicKey) *Verifier {
	return &Verifier{pk.Verify()}
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
	// creation time
	Created int64 `msgpack:"created"`
	// expiration time
	Expires int64 `msgpack:"expires,omitempty"`
	// revokation reason
	Reason string `msgpack:"reason,omitempty"`
}

//nolint:errcheck
func (v Validity) signEncode(w io.Writer) {
	w.Write(MarshalTime(v.Created))
	w.Write(MarshalTime(v.Expires))
	io.WriteString(w, v.Reason)
}

// IsRevoked returns true if the validity is revoked.
func (v Validity) IsRevoked() bool { return v.Reason != "" }

// IsExpired returns true if the validity is expired.
func (v Validity) IsExpired(t int64) bool { return v.Expires > 0 && v.Expires <= t }

// IsValid returns true if the validity neither expired nor revoked.
func (v Validity) IsValid(t int64) bool { return !v.IsRevoked() && !v.IsExpired(t) }

// Revoke returns a revoked copy of the validity.
func (v Validity) Revoke(t int64, reason string) Validity {
	v.Created = t
	v.Reason = reason
	return v
}

// Validate returns an error if the validity has incorrect values.
func (v Validity) Validate() error {
	if v.Created < 0 || v.Expires < 0 {
		return errors.New("unix time is negative")
	} else if v.Expires > 0 && v.Expires < v.Created {
		return errors.New("invalid expiration time")
	}
	return nil
}
