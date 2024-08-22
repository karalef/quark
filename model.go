package quark

import (
	"github.com/karalef/quark/keys"
	"github.com/karalef/quark/keys/sign"
)

type idModel struct {
	Public  *keys.Model     `msgpack:"public,omitempty"`
	Private *sign.Encrypted `msgpack:"private,omitempty"`

	Bindings       []Binding   `msgpack:"bindings,omitempty"`
	Certifications []Signature `msgpack:"certifications"`
	Self           Signature   `msgpack:"selfSignature,omitempty"`
	Created        int64       `msgpack:"created,omitempty"`
}

// UnpackError is an error that occurs when unpacking an identity.
type UnpackError string

func (e UnpackError) Error() string {
	return "identity unpacking error: " + string(e)
}
