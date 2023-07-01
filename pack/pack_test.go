package pack

import (
	"bytes"
	"testing"
)

var _ Packable = (*testPack)(nil)

type testPack struct {
	Test string `msgpack:"test"`
}

func (*testPack) PacketTag() Tag {
	return 0x01
}

func TestPacking(t *testing.T) {
	RegisterPacketType(NewType((*testPack)(nil), "test", "TEST BLOCK"))

	testValue := &testPack{
		Test: "test",
	}

	buf := new(bytes.Buffer)

	out, err := ArmoredEncoder(buf, testValue.PacketTag().BlockType(), map[string]string{"test": "test"})
	if err != nil {
		t.Fatal(err)
	}

	err = Pack(out, testValue)
	if err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}

	t.Log("\n", buf.String())

	blockType, header, in, err := Dearmor(buf)
	if err != nil {
		t.Fatal(err)
	}
	if blockType != testValue.PacketTag().BlockType() || len(header) == 0 {
		t.Fatal("unexpected armor block")
	}

	v := new(testPack)
	err = UnpackExact(in, v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Test != "test" {
		t.Fatal("unexpected data")
	}
}
