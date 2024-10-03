package quark

import (
	"github.com/karalef/quark/crypto/sign"
)

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

// Model contains packed Key.
type Model struct {
	Key            KeyModel         `msgpack:"key,omitempty"`
	Certificates   []RawCertificate `msgpack:"certificates,omitempty"`
	Certifications []Signature      `msgpack:"certifications"`
	Self           Signature        `msgpack:"selfSignature,omitempty"`
	Created        int64            `msgpack:"created,omitempty"`
}

// UnpackKey unpacks key from the model.
func (m Model) UnpackKey() (sign.PublicKey, error) {
	return sign.UnpackPublic(m.Key.Algorithm, m.Key.Key)
}
