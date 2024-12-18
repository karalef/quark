package subkey_test

import (
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/subkey"
)

func TestKey(t *testing.T) {
	k, sk, err := quark.Generate(sign.EDDilithium3, quark.NewValidity(0, 0))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	v := quark.NewValidity(now, now+3600)
	sub1, _, err := subkey.GenerateSign(sign.EDDilithium2)
	if err != nil {
		t.Fatal(err)
	}
	err = k.Sign(sk, sub1.Certificate(), v)
	if err != nil {
		t.Fatal(err)
	}
	sub2, _, err := subkey.GenerateKEM(kem.Kyber768)
	if err != nil {
		t.Fatal(err)
	}
	err = k.Sign(sk, sub2.Certificate(), v)
	if err != nil {
		t.Fatal(err)
	}

	err = k.Verify(sub1.Certificate(), sub1.Signature)
	if err != nil {
		t.Fatal(err)
	}
	err = k.Verify(sub2.Certificate(), sub2.Signature)
	if err != nil {
		t.Fatal(err)
	}
}
