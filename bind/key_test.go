package bind

import (
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encaps"
	"github.com/karalef/quark/pack"
)

func TestIdentity(t *testing.T) {
	id, sk, err := quark.Generate(sign.EDDilithium3, time.Now().Add(1000*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Verify(); err != nil {
		t.Fatal(err)
	}

	spk, _ := func() (quark.PublicKey, quark.PrivateKey) {
		sk, pk, err := sign.Generate(sign.EDDilithium2, nil)
		if err != nil {
			t.Fatal(err)
		}
		return quark.Keys(pk, sk)
	}()
	b, err := Key(id, sk, "", spk, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	kpk, _ := func() (encaps.PublicKey, encaps.PrivateKey) {
		pk, sk, err := encaps.Generate(kem.Kyber768)
		if err != nil {
			t.Fatal(err)
		}
		return pk, sk
	}()
	b, err = KEM(id, sk, "", kpk, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	printBindings(id.Bindings(), t)

	_, err = id.Unbind(b.ID, sk, "dont wanna see it")
	if err != nil {
		t.Fatal(err)
	}
	t.Log()
	printBindings(id.Bindings(), t)
}

func printBindings(binds []Binding, t *testing.T) {
	for _, bind := range binds {
		data := bind.Data
		switch bind.Type {
		case TypeSignKey:
			pk, err := DecodeKey(bind)
			if err != nil {
				t.Fatal(err)
			}
			data = pack.Raw(pk.Fingerprint().String())
		case TypeKEMKey:
			pk, err := DecodeKEM(bind)
			if err != nil {
				t.Fatal(err)
			}
			data = pack.Raw(pk.Fingerprint().String())
		}
		bindid := bind.ID.String()
		t.Logf("binding %s...%s: %s %s %s", bindid[:4], bindid[len(bindid)-4:], bind.Group, bind.Type, string(data))
		if bind.Signature.Validity.Revoked != 0 {
			t.Logf("revoked at %s because %s", time.Unix(bind.Signature.Validity.Revoked, 0), bind.Signature.Validity.Reason)
		} else {
			t.Logf("signed by %s and valid before %s", bind.Signature.Issuer.ID().String(), time.Unix(bind.Signature.Validity.Expires, 0))
		}
		t.Log()
	}
}
