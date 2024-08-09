package quark

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

type idModel struct {
	Public  *KeyModel     `msgpack:"public,omitempty"`
	Private *EncryptedKey `msgpack:"private,omitempty"`

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
