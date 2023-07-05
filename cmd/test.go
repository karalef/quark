package main

import (
	"bytes"

	"github.com/vmihailenco/msgpack/v5"
)

type abc struct {
	_msgpack struct{} `msgpack:",as_array"`
	String1  string
	Int1     int
}

func main() {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(abc{
		String1: "abc",
	})
	println(buf.String())

	dec := msgpack.NewDecoder(buf)
	l, _ := dec.DecodeArrayLen()
	println(l)
}
