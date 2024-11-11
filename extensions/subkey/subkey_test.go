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

func TestKey(t *testing.T) {
	k, sk, err := quark.Generate(sign.EDDilithium3)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.Verify(k.Key(), k.SelfSignature()); err != nil {
		t.Fatal(err)
	}

	_, spk, err := sign.Generate(sign.EDDilithium2, nil)
	if err != nil {
		t.Fatal(err)
	}
	bid, err := subkey.Bind(k, sk, time.Now().Add(time.Hour).Unix(), spk)
	if err != nil {
		t.Fatal(err)
	}

	_, kpk, err := kem.Generate(kem.Kyber768, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.Bind(k, sk, time.Now().Add(time.Hour).Unix(), kpk)
	if err != nil {
		t.Fatal(err)
	}
	printBindings(k.Bindings(), t)

	err = k.RevokeBinding(bid, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}
	t.Log()
	printBindings(k.Bindings(), t)
}

func printBindings(binds []quark.RawCertificate, t *testing.T) {
	for _, bind := range binds {
		var key crypto.Key
		switch bind.Type {
		case subkey.TypeSignKey, subkey.TypeKEMKey:
			sub, err := subkey.FromRaw(bind)
			if err != nil {
				t.Fatal(err)
			}
			key = sub.Key()
		}
		bindid := bind.ID.ID().String()
		t.Logf("binding %s: %s %s", bindid, bind.Type, key.ID().String())
		if bind.Validity().IsRevoked() {
			t.Logf("revoked at %s because %s",
				time.Unix(bind.Validity().Created, 0).Format(time.DateOnly),
				bind.Validity().Reason)
		} else {
			t.Logf("signed by %s and valid before %s",
				bind.Signature.Issuer.ID().String(),
				time.Unix(bind.Validity().Expires, 0).Format(time.DateOnly))
		}
		t.Log()
	}
}
