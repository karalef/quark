package pack

import (
	"bytes"
	"testing"
)

var _ Packable = (*testPack)(nil)

var testPacketType = NewType(0x1, (*testPack)(nil), "test", "TEST BLOCK")

type testPack struct {
	Test string `msgpack:"test"`
}

func (*testPack) PacketTag() Tag {
	return testPacketType.Tag
}

func TestPacking(t *testing.T) {
	RegisterPacketType(testPacketType)

	tt := &testPack{
		Test: "test",
	}

	buf := new(bytes.Buffer)

	out, err := ArmoredEncoder(buf, tt.PacketTag().BlockType(), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = Pack(out, tt,
		WithCompression(Zstd(0)),
		WithEncryption("test", nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}

	println(buf.Len())

	blockType, header, in, err := Dearmor(buf)
	if err != nil {
		t.Fatal(err)
	}
	if blockType != tt.PacketTag().BlockType() || len(header) != 0 {
		t.Fatal("unexpected armor block")
	}

	tag, v, err := Unpack(in,
		WithPassphrase(func() (string, error) { return "test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}

	if tag != testPacketType.Tag {
		t.Fatal("unexpected tag")
	}

	tt2, ok := v.(*testPack)
	if !ok {
		t.Fatal("unexpected type")
	}

	if tt2.Test != "test" {
		t.Fatal("unexpected data")
	}
}
