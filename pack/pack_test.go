package pack

import (
	"bytes"
	"testing"

	"github.com/karalef/quark/pack/armor"
)

var _ Packable = (*testPack)(nil)

type testPack struct {
	Test string `msgpack:"test"`
}

func (*testPack) PacketTag() Tag { return 65535 }

func TestPacking(t *testing.T) {
	testValue := &testPack{
		Test: "test",
	}
	RegisterPacketType(NewType(testValue, "test"))

	buf := new(bytes.Buffer)

	out, err := armor.Encode(buf, testValue.PacketTag().BlockType(), map[string]string{"test": "test"})
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

	block, err := armor.Dearmor(buf)
	if err != nil {
		t.Fatal(err)
	}
	if block.Type != testValue.PacketTag().BlockType() || len(block.Header) == 0 {
		t.Fatal("unexpected armor block")
	}

	v, err := Unpack(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	val, ok := v.(*testPack)
	if !ok {
		t.Fatal("wrong type")
	}

	if val.Test != "test" {
		t.Fatal("unexpected data")
	}
}
