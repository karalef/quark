package quark

import (
	"testing"
	"time"

	"github.com/karalef/quark/crypto/sign"
)

func TestIdentity(t *testing.T) {
	id, sk, err := Generate(sign.EDDilithium3, time.Now().Add(1000*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Verify(id.Key(), id.SelfSignature()); err != nil {
		t.Fatal(err)
	}

	_, err = id.Bind(sk, BindingData{
		Type: "id.nickname",
		Data: []byte("karalef"),
	}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	b, err := id.Bind(sk, BindingData{
		Type: BindTypeGroupQuark,
		Data: []byte("trash"),
	}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	_, err = id.RevokeBinding(b.ID, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}

	binds := id.Bindings()
	for _, bind := range binds {
		t.Logf("binding %s: %s %v %s", bind.ID, bind.Type, bind.Metadata, string(bind.Data))
		if bind.Signature.Validity.Revoked != 0 {
			t.Logf("revoked at %s because %s", time.Unix(bind.Signature.Validity.Revoked, 0), bind.Signature.Validity.Reason)
		} else {
			t.Logf("signed by %s and valid before %s", bind.Signature.Issuer.ID().String(), time.Unix(bind.Signature.Validity.Expires, 0))
		}
		t.Log()
	}
}
