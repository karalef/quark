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

	err := Pack(buf, tt,
		WithCompression(Flate, 0),
		WithEncryption("test", nil),
		WithArmor(map[string]string{
			"test": "test",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	tag, v, err := Unpack(buf,
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
