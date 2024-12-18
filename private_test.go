package quark_test

import (
	"testing"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/password"
)

func TestKey(t *testing.T) {
	sk, _, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := quark.EncryptKey(sk, "password", nil, encrypted.NewPassphraseFrom(
		password.Build(aead.ChaCha20Poly1305, kdf.FromHash(hash.SHA256)),
		kdf.NewNoCost(),
		16,
	))
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
