package subkey_test

import (
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/subkey"
)

func TestIdentity(t *testing.T) {
	id, sk, err := quark.Generate(sign.EDDilithium3, time.Now().Add(1000*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Verify(id.Key(), id.SelfSignature()); err != nil {
		t.Fatal(err)
	}

	_, spk, err := sign.Generate(sign.EDDilithium2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.BindSign(id, sk, spk, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	_, kpk, err := kem.Generate(kem.Kyber768, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := subkey.BindKEM(id, sk, kpk, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	printBindings(id.Bindings(), t)

	_, err = id.RevokeBinding(b.ID, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}
	t.Log()
	printBindings(id.Bindings(), t)
}

func printBindings(binds []quark.RawBinding, t *testing.T) {
	for _, bind := range binds {
		var key crypto.KeyID
		switch bind.BindType() {
		case subkey.TypeSignKey:
			sub, err := quark.BindingAs[subkey.SignSubkey](bind)
			if err != nil {
				t.Fatal(err)
			}
			key = sub.GetData()
		case subkey.TypeKEMKey:
			sub, err := quark.BindingAs[subkey.KEMSubkey](bind)
			if err != nil {
				t.Fatal(err)
			}
			key = sub.GetData()
		}
		bindid := bind.ID.ShortString()
		t.Logf("binding %s: %s %s", bindid, bind.BindType(), key.ID().String())
		if bind.Validity().IsRevoked(time.Now().Unix()) {
			t.Logf("revoked at %s because %s",
				time.Unix(bind.Validity().Revoked, 0).Format(time.DateOnly),
				bind.Validity().Reason)
		} else {
			t.Logf("signed by %s and valid before %s",
				bind.Signature.Issuer.ID().String(),
				time.Unix(bind.Validity().Expires, 0).Format(time.DateOnly))
		}
		t.Log()
	}
}
