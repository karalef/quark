package quark

import (
	"encoding/binary"
	"errors"

	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/internal"
)

// SignStream creates a sign.Signer and writes the current time to it.
func SignStream(issuer Private, time int64) (sign.Signer, error) {
	return signStream(issuer.Sign(), time)
}

func signStream(issuer sign.PrivateKey, time int64) (sign.Signer, error) {
	signer := issuer.Signer()

	_, err := signer.Write(MarshalTime(time))
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// VerifyStream creates a sign.Verifier and writes the current time to it.
func VerifyStream(issuer Public, time int64) (sign.Verifier, error) {
	return verifyStream(issuer.Sign(), time)
}

func verifyStream(issuer sign.PublicKey, time int64) (sign.Verifier, error) {
	verifier := issuer.Verifier()

	_, err := verifier.Write(MarshalTime(time))
	if err != nil {
		return nil, err
	}

	return verifier, nil
}

// MarshalTime encodes a unix time into a byte array.
func MarshalTime(time int64) []byte {
	var binTime [8]byte
	binary.LittleEndian.PutUint64(binTime[:], uint64(time))
	return binTime[:]
}

// Signature represents a signature.
type Signature []byte

// Copy returns a copy of the signature.
func (s Signature) Copy() Signature {
	return internal.Copy(s)
}

// IsValid returns true if the signature is valid.
func (s Signature) IsValid() bool {
	return s.Error() == ""
}

// Validate compares the signature against the public keyset id and scheme.
func (s Signature) Validate(pub Public) error {
	if len(s) != pub.Scheme().Sign.SignatureSize() {
		return errors.New("invalid signature size")
	}
	return nil
}

func (s Signature) Error() string {
	switch {
	case s == nil || len(s) == 0:
		return "empty signature"
	}
	return ""
}

// CertificationSignature represents a certification signature.
type CertificationSignature struct {
	Signature Signature `msgpack:"sig"`
	Time      int64     `msgpack:"time"`
	Issuer    ID        `msgpack:"issuer"`
}

// Copy returns a copy of the certification signature.
func (s CertificationSignature) Copy() CertificationSignature {
	s.Signature = s.Signature.Copy()
	return s
}
