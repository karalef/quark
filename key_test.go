package quark

import (
	"testing"
	"time"

	"github.com/karalef/quark/crypto/sign"
)

type StringBind string

func (s StringBind) CertType() string {
	return "bind.string"
}

func (s StringBind) Copy() StringBind {
	return s
}

func TestKey(t *testing.T) {
	k, sk, err := Generate(sign.EDDilithium3)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.Verify(k.Key(), k.SelfSignature()); err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour).Unix()
	_, err = Bind(k, sk, exp, StringBind("karalef"))
	if err != nil {
		t.Fatal(err)
	}

	bid, err := Bind(k, sk, exp, StringBind("trash"))
	if err != nil {
		t.Fatal(err)
	}

	err = k.RevokeBinding(bid, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}

	binds := k.Bindings()
	for _, bind := range binds {
		bind, err := CertificateAs[StringBind](bind)
		if err != nil {
			t.Fatal(err)
		}
		data := bind.Data
		val := bind.Validity()
		t.Logf("binding %s: %s %s", bind.ID.ID().String(), bind.Type, data)
		if val.IsRevoked() {
			t.Logf("revoked at %s because %s", time.Unix(val.Created, 0), val.Reason)
		} else {
			issuer := bind.Signature.Issuer.ID()
			t.Logf("signed by %s and valid before %s", issuer.String(), time.Unix(val.Expires, 0))
		}
		t.Log()
	}
}
