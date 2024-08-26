package quark

import (
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/keys"
)

type idModel struct {
	Public  *keys.Model   `msgpack:"public,omitempty"`
	Private *EncryptedKey `msgpack:"private,omitempty"`

	Bindings       []Binding   `msgpack:"bindings,omitempty"`
	Certifications []Signature `msgpack:"certifications"`
	Self           Signature   `msgpack:"selfSignature,omitempty"`
	Created        int64       `msgpack:"created,omitempty"`
}

func (m idModel) UnpackKey() (PublicKey, error) {
	if m.Public == nil {
		return nil, UnpackError("object does not contain public key")
	}
	scheme := sign.ByName(m.Public.Algorithm)
	if scheme == nil {
		return nil, UnpackError("scheme not found: " + m.Public.Algorithm)
	}
	if len(m.Public.Key) != scheme.PublicKeySize() {
		return nil, UnpackError("invalid public key size")
	}
	key, err := scheme.UnpackPublic(m.Public.Key)
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
