package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
)

// KeyModel returns the key model.
func NewKeyModel(key crypto.RawKey) KeyModel {
	return KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}
}

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

// Model contains packed Key.
type Model struct {
	Key            KeyModel         `msgpack:"key,omitempty"`
	Bindings       []RawCertificate `msgpack:"bindings,omitempty"`
	Certifications []Signature      `msgpack:"certifications"`
	Self           Signature        `msgpack:"selfSignature,omitempty"`
	Created        int64            `msgpack:"created,omitempty"`
}

// UnpackKey unpacks key from the model.
func (m Model) UnpackKey() (sign.PublicKey, error) {
	return sign.UnpackPublic(m.Key.Algorithm, m.Key.Key)
}
