package quark

import (
	"bytes"
	"errors"
	"io"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// CertID represents a certificate ID.
type CertID = crypto.Fingerprint

// Copier interface.
type Copier[T any] interface {
	// Copy returns a copy of the object.
	// The returned value must be the same type.
	Copy() T
}

// RawData represents a msgpack raw message and implements the Copier interface.
type RawData []byte

func (r RawData) Copy() RawData { return crypto.Copy(r) }

func (r RawData) EncodeMsgpack(enc *pack.Encoder) error {
	_, err := enc.Writer().Write(r)
	return err
}

func (r *RawData) DecodeMsgpack(dec *pack.Decoder) error {
	d, err := dec.DecodeRaw()
	if err != nil {
		return err
	}
	*r = RawData(d)
	return nil
}

// CertData interface.
type CertData[T Copier[T]] interface {
	// CertType returns the certificate type.
	CertType() string

	Copier[T]
}

// Certifyable represents an object that can be certified.
type Certifyable[T CertData[T]] interface {
	CertData[T]
}

// NewCertificate creates a new unsigned certificate.
func NewCertificate[T Certifyable[T]](data T) Certificate[T] {
	c := Certificate[T]{
		Type: data.CertType(),
		Data: data.Copy(),
	}
	c.ID = c.CalcID()
	return c
}

// Certificate contains data with signature.
type Certificate[Type Certifyable[Type]] struct {
	ID        CertID    `msgpack:"id"`
	Type      string    `msgpack:"type"`
	Data      Type      `msgpack:"data"`
	Signature Signature `msgpack:"sig"`
}

// RawCertifyable represents a certifyable that holds raw data.
type RawCertifyable struct {
	Type string
	RawData
}

func (r RawCertifyable) CertType() string { return r.Type }
func (r RawCertifyable) Copy() RawCertifyable {
	r.RawData = r.RawData.Copy()
	return r
}

// RawCertificate represents a certificate with raw data.
type RawCertificate = Certificate[RawCertifyable]

// Raw returns the certificate with raw data.
func (c Certificate[Type]) Raw() RawCertificate {
	b := bytes.NewBuffer(nil)
	err := pack.EncodeBinary(b, c.Data)
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	return RawCertificate{
		ID:        c.ID,
		Type:      c.Type,
		Data:      RawCertifyable{Type: c.Type, RawData: b.Bytes()},
		Signature: c.Signature.Copy(),
	}
}

// Copy returns a copy of the certificate.
func (c Certificate[Type]) Copy() Certificate[Type] {
	c.Data = c.Data.Copy()
	c.Signature = c.Signature.Copy()
	return c
}

// CheckIntegrity validates the certificate integrity without signature verification.
func (c Certificate[Data]) CheckIntegrity() bool {
	return c.ID == c.CalcID()
}

// CalcID calculates the certificate ID.
func (c Certificate[Data]) CalcID() CertID {
	return crypto.FingerprintFunc(func(w io.Writer) {
		w.Write([]byte(c.Type))
		if err := pack.EncodeBinary(w, c.Data); err != nil {
			panic("unexpected error: " + err.Error())
		}
	})
}

// SignEncode implements Signable.
func (c Certificate[Data]) SignEncode(w io.Writer) error {
	w.Write(c.ID[:])
	w.Write([]byte(c.Type))
	err := pack.EncodeBinary(w, c.Data)
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	return nil
}

// Sign signs the certificate.
func (c *Certificate[Data]) Sign(sk sign.PrivateKey, v Validity) error {
	sig, err := SignObject(sk, v, c)
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// Verify verifies the certificate signature.
func (c Certificate[Data]) Verify(pk sign.PublicKey) (bool, error) {
	return c.Signature.VerifyObject(pk, c)
}

// Validity returns the validity of the certificate.
func (c Certificate[Data]) Validity() Validity { return c.Signature.Validity }

// Validate validates the certificate.
func (c Certificate[Data]) Validate() error {
	if c.ID.IsEmpty() || c.Type == "" || !c.CheckIntegrity() {
		return ErrCertMalformed
	}
	if t := c.Data.CertType(); t != "" && c.Type != t {
		return ErrWrongCertType
	}
	return nil
}

// CertificateAs converts a raw certificate to a typed certificate.
func CertificateAs[T Certifyable[T]](cert RawCertificate) (Certificate[T], error) {
	constrained := Certificate[T]{
		ID:        cert.ID,
		Type:      cert.Type,
		Signature: cert.Signature.Copy(),
	}
	err := pack.DecodeBinary(bytes.NewReader(cert.Data.RawData), &constrained.Data)
	if err != nil {
		return Certificate[T]{}, err
	}
	return constrained, constrained.Validate()
}

var (
	ErrWrongCertType = errors.New("wrong certificate type")
	ErrCertMalformed = errors.New("malformed certificate")
)
