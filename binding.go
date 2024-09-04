package quark

import (
	"bytes"
	"errors"
	"strings"

	"github.com/karalef/quark/pack"
)

// CertTypeBind is the type for binding certificates.
const CertTypeBind = "bind"

// BindTypeGroupQuark is the types group for the quark types.
const BindTypeGroupQuark BindType = "quark"

// BindType represents a binding object type.
type BindType string

func (b BindType) String() string { return string(b) }

// Add adds the next type to the current one.
func (b BindType) Add(next BindType) BindType {
	norm := strings.TrimPrefix(string(next), ".")
	if len(norm) == 0 {
		return b
	}
	return BindType(string(b) + "." + norm)
}

// Group returns the global type group of the type.
func (b BindType) Group() BindType { return b[:strings.IndexByte(string(b), '.')] }

// InGroup returns true if the type is in the group.
func (b BindType) InGroup(g BindType) bool { return strings.HasPrefix(string(b), string(g)) }

// Type returns the final object type.
func (b BindType) Type() BindType { return b[strings.LastIndexByte(string(b), '.')+1:] }

// BindData interface.
type BindData[T Copier[T]] interface {
	// BindType returns the binding type.
	BindType() BindType

	Copier[T]
}

// Bindable represents an object that can be bound.
type Bindable[T BindData[T]] interface {
	BindData[T]
}

// NewBinding creates a new unsigned binding.
func NewBinding[T Bindable[T]](data T) Binding[T] {
	if data.BindType() == "" {
		panic("invalid data")
	}
	return Binding[T](NewCertificate(BindingData[T]{
		Type: data.BindType(),
		Data: data,
	}))
}

// ErrWrongBindType is returned when an wrong binding type is provided.
var ErrWrongBindType = errors.New("wrong binding type")

// Binding represents an identity binding.
type Binding[T Bindable[T]] Certificate[BindingData[T]]

func (b Binding[T]) BindType() BindType { return b.Data.Type }
func (b Binding[T]) GetData() T         { return b.Data.Data }

func (b *Binding[T]) Cert() *Certificate[BindingData[T]] { return (*Certificate[BindingData[T]])(b) }
func (b Binding[T]) Validity() Validity                  { return b.Signature.Validity }
func (b Binding[T]) Copy() Binding[T]                    { return Binding[T](b.Cert().Copy()) }
func (b Binding[T]) Validate() error                     { return b.Cert().Validate() }
func (b Binding[T]) Raw() RawBinding {
	return RawBinding{
		ID:        b.ID,
		Type:      b.Type,
		Data:      b.Data.Raw(),
		Signature: b.Signature,
	}
}

// RawBinding represents a binding that holds raw data.
type RawBinding = Binding[RawBindable]

// RawBindable represents a bindable that holds raw data.
type RawBindable struct {
	RawData
	Type BindType
}

func (b RawBindable) BindType() BindType { return b.Type }
func (b RawBindable) Copy() RawBindable {
	b.RawData = b.RawData.Copy()
	return b
}

type BindingData[T Bindable[T]] struct {
	Type BindType `msgpack:"type"`
	Data T        `msgpack:"data"`
}

func (b BindingData[T]) BindType() BindType { return b.Type }
func (BindingData[T]) CertType() string     { return CertTypeBind }
func (b BindingData[T]) Copy() BindingData[T] {
	b.Data = b.Data.Copy()
	return b
}

func (b BindingData[T]) Raw() BindingData[RawBindable] {
	switch b := any(b).(type) {
	case BindingData[RawBindable]:
		return b
	}
	buf := bytes.NewBuffer(nil)
	err := pack.EncodeBinary(buf, b.Data)
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	return BindingData[RawBindable]{
		Type: b.Type,
		Data: RawBindable{Type: b.Type, RawData: buf.Bytes()},
	}
}

// BindingAs converts a raw binding to a typed binding.
func BindingAs[T Bindable[T]](b RawBinding) (Binding[T], error) {
	cert, err := CertificateAs[BindingData[T]](b.Cert().Raw())
	if err != nil {
		return Binding[T]{}, err
	}
	return Binding[T](cert), nil
}
