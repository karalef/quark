package quark

import (
	"errors"
	"time"
)

// Sign creates a signature.
// Returns an empty signature without error if the keyset is nil.
func Sign(plaintext []byte, keyset Private) (*Signature, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("Sign: empty data")
	}
	if keyset == nil {
		return nil, nil
	}

	signature, err := keyset.Sign().Sign(plaintext)
	if err != nil {
		return nil, err
	}

	return &Signature{
		ID:        keyset.ID(),
		Signature: signature,
		Time:      time.Now().Unix(),
	}, nil
}

// Verify verifies a signature.
func Verify(data []byte, signature Signature, keyset Public) (bool, error) {
	err := signature.Validate(keyset)
	if err != nil {
		return false, err
	}
	return keyset.Sign().Verify(data, signature.Signature)
}

// Signature represents a signature.
type Signature struct {
	// keyset id used for signing
	ID ID `msgpack:"id"`

	// signature
	Signature []byte `msgpack:"sig"`

	// signature time stamp
	Time int64 `msgpack:"time"`
}

// IsValid returns true if the signature is valid.
func (s *Signature) IsValid() bool {
	return s.Error() == ""
}

// Validate compares the signature against the public keyset id and scheme.
func (s *Signature) Validate(pub Public) error {
	if s.ID != pub.ID() {
		return errors.New("wrong recipient")
	}
	if len(s.Signature) != pub.Scheme().Sign.SignatureSize() {
		return errors.New("invalid signature size")
	}
	if s.Time > time.Now().Unix() {
		return errors.New("the time of signature creation is the time in the future")
	}
	return nil
}

func (s *Signature) Error() string {
	switch {
	case s == nil || len(s.Signature) == 0:
		return "empty signature"
	case s.ID.IsEmpty():
		return "empty keyset id"
	case s.Time > time.Now().Unix():
		return "the time of signature creation is the time in the future"
	}
	return ""
}
