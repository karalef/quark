package key_test

import (
	"testing"

	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted/key"
)

func TestKey(t *testing.T) {
	sk, _, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := key.Encrypt(sk, "password", nil, passParams.New())
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := k.DecryptSign("password")
	if err != nil {
		t.Fatal(err)
	}

	if !sk.Equal(sk2) {
		t.Fatal("mismatch")
	}
}
