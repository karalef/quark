package binary

import (
	"bytes"
	"testing"
)

func TestStream(t *testing.T) {
	testData := bytes.Repeat([]byte("hello"), 32*1024)
	s := &Stream{
		Reader: bytes.NewReader(testData),
	}

	buf := new(bytes.Buffer)
	err := Encode(buf, s)
	if err != nil {
		t.Fatal(err)
	}

	dataBuf := bytes.NewBuffer(make([]byte, 0, len(testData)))
	s.Writer = dataBuf

	err = Decode(buf, s)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dataBuf.Bytes(), testData) {
		t.Fatal("unexpected result")
	}
}
