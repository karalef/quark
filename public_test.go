package quark

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

func TestPublic(t *testing.T) {
	_, pk, err := sign.Generate(sign.EDDilithium2, nil)
	if err != nil {
		t.Fatal(err)
	}

	k := NewPublicKey[sign.PublicKey](pk)

	buf := bytes.NewBuffer(nil)
	err = pack.Pack(buf, &k)
	if err != nil {
		t.Fatal(err)
	}

	kd, err := pack.Unpack(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(reflect.TypeOf(kd))
}
