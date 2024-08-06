package quark

import (
	"strings"

	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/pkg/crockford"
)

// BindTypeGroupQuark is the types group for the quark types.
const BindTypeGroupQuark BindType = "quark"

// BindTypeGroupID is the global ID types group.
const BindTypeGroupID BindType = "id"

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

// BindID represents a binding ID.
type BindID [32]byte

// IsEmpty returns true if the ID is empty.
func (b BindID) IsEmpty() bool { return b == BindID{} }

func (b BindID) String() string { return crockford.Upper.EncodeToString(b[:]) }

// NewBinding returns a new binding.
func NewBinding(key PublicKey, d BindingData) Binding {
	b := Binding{
		Type:  d.Type,
		Group: d.Group,
		Data:  d.Data,
	}
	b.ID = b.calcID(key)
	return b
}

// ShortBinding represents a part of the binding.
// It is used for listing bindings without signature and data copying.
type ShortBinding struct {
	ID    BindID
	Type  BindType
	Group string
}

// BindingData represents a binding data.
type BindingData struct {
	Type  BindType
	Group string
	Data  []byte
}

// Binding represents an identity binding.
type Binding struct {
	ID        BindID    `msgpack:"id"`
	Type      BindType  `msgpack:"type"`
	Group     string    `msgpack:"group,omitempty"`
	Data      []byte    `msgpack:"data"`
	Signature Signature `msgpack:"sig"`
}

// Short returns a short version of the binding.
func (b Binding) Short() ShortBinding {
	return ShortBinding{
		ID:    b.ID,
		Type:  b.Type,
		Group: b.Group,
	}
}

// BindingData returns a copy of the binding data.
func (b Binding) BindingData() BindingData {
	return BindingData{
		Type:  b.Type,
		Group: b.Group,
		Data:  internal.Copy(b.Data),
	}
}

// Copy returns a copy of the binding.
func (b Binding) Copy() Binding {
	b.Data = internal.Copy(b.Data)
	b.Signature = b.Signature.Copy()
	return b
}

// CheckIntegrity validates the binding integrity.
func (b Binding) CheckIntegrity(pk PublicKey) bool {
	return b.ID == b.calcID(pk)
}

func (b Binding) calcID(pk PublicKey) (id BindID) {
	h := hash.SHA3_256.New()
	h.Write(pk.Fingerprint().Bytes())
	h.Write([]byte(b.Group))
	h.Write([]byte(b.Type))
	h.Write(b.Data)
	return BindID(h.Sum(id[:0]))
}

func (b *Binding) sign(sk PrivateKey, v Validity) error {
	signer := SignStream(sk)
	signer.Write(b.ID[:])
	signer.Write([]byte(b.Group))
	signer.Write([]byte(b.Type))
	signer.Write(b.Data)
	sig, err := signer.Sign(v)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}
