package keys

// Model contains packed immutable parts of the key.
type Model struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}
