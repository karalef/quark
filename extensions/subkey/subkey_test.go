package subkey_test

import (
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/subkey"
	"github.com/karalef/quark/pack"
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
	b, err := subkey.Bind(id, sk, nil, spk, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	_, kpk, err := kem.Generate(kem.Kyber768, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err = subkey.Bind(id, sk, nil, kpk, time.Now().Add(time.Hour).Unix())
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

func printBindings(binds []quark.Binding, t *testing.T) {
	for _, bind := range binds {
		data := bind.Data
		switch bind.Type {
		case subkey.TypeSignKey:
			pk, err := subkey.DecodeSign(bind)
			if err != nil {
				t.Fatal(err)
			}
			data = pack.Raw(pk.Fingerprint().String())
		case subkey.TypeKEMKey:
			pk, err := subkey.DecodeKEM(bind)
			if err != nil {
				t.Fatal(err)
			}
			data = pack.Raw(pk.Fingerprint().String())
		}
		bindid := bind.ID.String()
		t.Logf("binding %s...%s: %s %v %s", bindid[:4], bindid[len(bindid)-4:], bind.Type, bind.Metadata, string(data))
		if bind.Signature.Validity.Revoked != 0 {
			t.Logf("revoked at %s because %s", time.Unix(bind.Signature.Validity.Revoked, 0), bind.Signature.Validity.Reason)
		} else {
			t.Logf("signed by %s and valid before %s", bind.Signature.Issuer.ID().String(), time.Unix(bind.Signature.Validity.Expires, 0))
		}
		t.Log()
	}
}
