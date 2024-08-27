package quark

import (
	"github.com/karalef/quark/crypto/sign"
)

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

type idModel struct {
	Key            KeyModel    `msgpack:"key,omitempty"`
	Bindings       []Binding   `msgpack:"bindings,omitempty"`
	Certifications []Signature `msgpack:"certifications"`
	Self           Signature   `msgpack:"selfSignature,omitempty"`
	Created        int64       `msgpack:"created,omitempty"`
}

func (m idModel) UnpackKey() (PublicKey, error) {
	if m.Key.Key == nil {
		return nil, UnpackError("object does not contain public key")
	}
	scheme := sign.ByName(m.Key.Algorithm)
	if scheme == nil {
		return nil, UnpackError("scheme not found: " + m.Key.Algorithm)
	}
	if len(m.Key.Key) != scheme.PublicKeySize() {
		return nil, UnpackError("invalid public key size")
	}
	key, err := scheme.UnpackPublic(m.Key.Key)
	if err != nil {
		return nil, UnpackError("invalid public key: " + err.Error())
	}
	return key, nil
}

// UnpackError is an error that occurs when unpacking an identity.
type UnpackError string

func (e UnpackError) Error() string {
	return "identity unpacking error: " + string(e)
}
