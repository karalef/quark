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

	// CertPacketTag returns the certificate packet tag.
	CertPacketTag() pack.Tag

	Copier[T]
	Signable
}

// Certifyable represents an object that can be certified.
type Certifyable[T CertData[T]] interface {
	CertData[T]
}

// Any represents any certificate.
type Any interface {
	Signable
	pack.Packable

	CertID() CertID
	CertType() string
	GetSignature() Signature
	CalcID() crypto.Fingerprint
	CheckIntegrity() bool
	Raw() Certificate[RawCertifyable]
	Sign(sign.PrivateKey, Validity) error
	Validate() error
}

// NewCertificate creates a new unsigned certificate.
func NewCertificate[T Certifyable[T]](data T) Certificate[T] {
	c := Certificate[T]{
		Data: data.Copy(),
		Type: data.CertType(),
	}
	c.ID = c.CalcID()
	return c
}

var _ Any = (*Raw)(nil)

// Certificate contains data with signature.
type Certificate[Type Certifyable[Type]] struct {
	ID        CertID    `msgpack:"id"`
	Type      string    `msgpack:"type"`
	Data      Type      `msgpack:"data"`
	Signature Signature `msgpack:"signature"`
}

func (*Certificate[Type]) PacketTag() pack.Tag {
	var v Type
	return v.CertPacketTag()
}

func (c Certificate[Type]) CertID() CertID          { return c.ID }
func (c *Certificate[Type]) CertType() string       { return c.Type }
func (c Certificate[Type]) GetSignature() Signature { return c.Signature }

// RawCertifyable represents a certifyable that holds raw data.
type RawCertifyable struct {
	Type string
	RawData
}

func (RawCertifyable) CertPacketTag() pack.Tag        { return PacketTagCertificate }
func (r RawCertifyable) CertType() string             { return r.Type }
func (r RawCertifyable) SignEncode(w io.Writer) error { _, err := w.Write(r.RawData); return err }
func (r RawCertifyable) Copy() RawCertifyable {
	r.RawData = r.RawData.Copy()
	return r
}

// Raw represents a certificate with raw data.
type Raw = Certificate[RawCertifyable]

// Raw returns the certificate with raw data.
func (c Certificate[_]) Raw() Raw {
	b := bytes.NewBuffer(nil)
	if err := pack.EncodeBinary(b, c.Data); err != nil {
		// encoding error (not writer) means that the certificate
		// data was not normally created.
		panic("unexpected error: " + err.Error())
	}
	return Raw{
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
func (c Certificate[_]) CheckIntegrity() bool { return c.ID == c.CalcID() }

// CalcID calculates the certificate ID.
func (c Certificate[_]) CalcID() CertID {
	return crypto.FingerprintFunc(func(w io.Writer) {
		w.Write([]byte(c.Type))
		if err := c.Data.SignEncode(w); err != nil {
			panic("unexpected error: " + err.Error())
		}
	})
}

// SignEncode implements Signable.
func (c Certificate[_]) SignEncode(w io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	w.Write(c.ID[:])
	w.Write([]byte(c.Type))
	return c.Data.SignEncode(w)
}

// Sign signs the certificate.
func (c *Certificate[_]) Sign(sk sign.PrivateKey, v Validity) error {
	sig, err := SignObject(sk, v, c)
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// Validate validates the certificate.
func (c Certificate[_]) Validate() error {
	if c.ID.IsEmpty() || c.Type == "" || !c.CheckIntegrity() {
		return ErrCertMalformed
	}
	if t := c.Data.CertType(); t != "" && c.Type != t {
		return ErrWrongCertType
	}
	return nil
}

// As converts a raw certificate to a typed certificate.
func As[T Certifyable[T]](cert Raw) (Certificate[T], error) {
	typed := Certificate[T]{
		ID:        cert.ID,
		Type:      cert.Type,
		Signature: cert.Signature.Copy(),
	}
	err := pack.DecodeBinary(bytes.NewReader(cert.Data.RawData), &typed.Data)
	if err != nil {
		return Certificate[T]{}, err
	}
	return typed, typed.Validate()
}

// To asserts the certificate type. Panics if the certificate type does not match.
func To[T Certifyable[T]](cert Any) *Certificate[T] {
	t, ok := cert.(*Certificate[T])
	if !ok {
		panic("invalid certificate type assertion")
	}
	if t.Type != t.Data.CertType() {
		panic(ErrWrongCertType)
	}
	return t
}

// certificate errors.
var (
	ErrWrongCertType = errors.New("wrong certificate type")
	ErrCertMalformed = errors.New("malformed certificate")
	ErrAlreadySigned = errors.New("already signed")
)
