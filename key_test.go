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
	id, sk, err := Generate(sign.EDDilithium3, time.Now().Add(1000*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err = id.Verify(id.Key(), id.SelfSignature()); err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour).Unix()
	_, err = Bind(id, sk, exp, StringBind("karalef"))
	if err != nil {
		t.Fatal(err)
	}

	b, err := Bind(id, sk, exp, StringBind("trash"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = id.RevokeBinding(b.ID, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}

	binds := id.Bindings()
	for _, bind := range binds {
		bind, err := CertificateAs[StringBind](bind)
		if err != nil {
			t.Fatal(err)
		}
		data := bind.Data
		val := bind.Validity()
		t.Logf("binding %s: %s %s", bind.ID.ShortString(), bind.Type, data)
		if val.IsRevoked() {
			t.Logf("revoked at %s because %s", time.Unix(val.Created, 0), val.Reason)
		} else {
			issuer := bind.Signature.Issuer.ID()
			t.Logf("signed by %s and valid before %s", issuer.String(), time.Unix(val.Expires, 0))
		}
		t.Log()
	}
}
