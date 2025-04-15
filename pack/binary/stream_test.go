package binary

import (
	"bytes"
	"hash/crc64"
	"io"
	"testing"
)

func TestStream(t *testing.T) {
	cs := crc64.New(crc64.MakeTable(crc64.ISO))

	testData := bytes.Repeat([]byte("hello"), 1024*1024)
	s := NewStream(io.TeeReader(bytes.NewReader(testData), cs))

	buf := new(bytes.Buffer)
	err := Encode(buf, s)
	if err != nil {
		t.Fatal(err)
	}

	checksum := cs.Sum64()
	cs.Reset()
	s.Writer = cs
	err = Decode(buf, s)
	if err != nil {
		t.Fatal(err)
	}
	if checksum != cs.Sum64() {
		t.Fatal("checksum mismatch")
	}
}
