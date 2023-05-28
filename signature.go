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

// Signature represents a signature.
type Signature struct {
	// keyset id used for signing
	ID ID `msgpack:"id"`

	// signature
	Signature []byte `msgpack:"sig"`

	// signature time stamp
	Time int64 `msgpack:"time"`
}

// IsEmpty returns true if the signature is empty.
func (s *Signature) IsEmpty() bool {
	if s == nil {
		return true
	}
	return s.ID == ID{} && len(s.Signature) == 0 && s.Time == 0
}

// IsValid returns true if the signature is valid.
func (s *Signature) IsValid() bool {
	if s.IsEmpty() {
		return false
	}
	return s.Time < time.Now().Unix()
}

func (s *Signature) Error() string {
	switch {
	case s.ID == ID{}:
		return "empty keyset id"
	case len(s.Signature) == 0:
		return "empty signature"
	case s.Time < time.Now().Unix():
		return "the time of signature creation is the time in the future"
	}
	return ""
}
