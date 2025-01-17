package pack_test

import (
	"bytes"
	"testing"

	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/pack/armor"
)

var _ pack.Packable = (*testPack)(nil)

type testPack struct {
	Test string `msgpack:"test"`
}

func (*testPack) PacketTag() pack.Tag { return 65535 }

func TestPacking(t *testing.T) {
	testValue := &testPack{
		Test: "test",
	}
	pack.RegisterPacketType(pack.NewType(testValue, "test"))

	buf := new(bytes.Buffer)

	out, err := armor.Encode(buf, testValue.PacketTag().BlockType(), map[string]string{"test": "test"})
	if err != nil {
		t.Fatal(err)
	}

	err = pack.Pack(out, testValue)
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

	v, err := pack.Unpack(block.Body)
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

func TestMulti(t *testing.T) {
	testValue := &testPack{"test"}
	pack.RegisterPacketType(pack.NewType(testValue, "test"))

	buf := new(bytes.Buffer)

	out, err := armor.Encode(buf, "COMPLEX OBJ", map[string]string{"test": "test"})
	if err != nil {
		t.Fatal(err)
	}

	packer := pack.NewPacker(out)
	for range 5 {
		err = packer.Pack(testValue)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}

	t.Log("\n", buf.String())

	block, err := armor.Dearmor(buf)
	if err != nil {
		t.Fatal(err)
	}
	if block.Type != "COMPLEX OBJ" || len(block.Header) == 0 {
		t.Fatal("unexpected armor block")
	}

	unpacker := pack.NewUnpacker(block.Body)
	for range 5 {
		val, err := unpacker.Unpack()
		if err != nil {
			t.Fatal(err)
		}
		test, ok := val.(*testPack)
		if !ok {
			t.Fatal("wrong type")
		}
		if test.Test != "test" {
			t.Fatal("unexpected data")
		}
	}
}
