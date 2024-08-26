package crockford

import (
	"bytes"
	"testing"
)

func TestCrock(t *testing.T) {
	e := Upper
	data := []byte("The quick brown fox jumps over the lazy dog.")
	out := e.EncodeToString(data)
	data2, err := e.DecodeString(string(out))
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("expected", data, "got", data2)
	}
	t.Log(string(out))
}
